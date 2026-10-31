//! Counterexample shrinking: a failing history is reduced greedily, one smaller variant at a
//! time, while it still fails. Each model's histories propose their variants (fewer writes,
//! nodes and actors, lower roles, fewer receipts, compacted times and commit IDs); every
//! variant is smaller in a well-founded order, so shrinking ends.

/// A history that proposes strictly smaller variants of itself.
pub trait Shrink: Sized {
    fn smaller(&self) -> Vec<Self>;
}

/// The smallest variant of `h` reachable by single steps that keep `fails` true. `h` itself
/// must fail.
pub fn shrink<H: Shrink>(mut h: H, mut fails: impl FnMut(&H) -> bool) -> H {
    'step: loop {
        for c in h.smaller() {
            if fails(&c) {
                h = c;
                continue 'step;
            }
        }
        return h;
    }
}

/// Receipt time of a write nobody but its author ever holds.
pub const LATE: u32 = 1000;

/// Order-preserving renumbering of `vals` (times compared with one another: write times,
/// receipts, `until`s, ledger keys) onto 0.. or 1.. (0 stays 0, so a write never moves to the
/// genesis time). `LATE` and anything above it (`NEVER`) are left alone. None if nothing
/// changes.
pub fn compact_times(vals: &[u32]) -> Option<impl Fn(u32) -> u32> {
    let mut d: Vec<u32> = vals.iter().copied().filter(|&v| v < LATE).collect();
    d.sort_unstable();
    d.dedup();
    let off = u32::from(d.first().map_or(false, |&v| v > 0));
    let map = move |v: u32| if v >= LATE { v } else { d.binary_search(&v).map_or(v, |i| i as u32 + off) };
    vals.iter().any(|&v| map(v) != v).then_some(map)
}

/// Order-preserving renumbering of distinct commit IDs onto 1..; None if nothing changes.
pub fn compact_ids<T: Copy + Ord + TryFrom<usize>>(ids: &[T]) -> Option<Vec<T>> {
    let mut d = ids.to_vec();
    d.sort_unstable();
    d.dedup();
    let out: Vec<T> = ids.iter().map(|v| T::try_from(d.binary_search(v).unwrap_or(0) + 1).ok().unwrap_or(*v)).collect();
    (out != ids).then_some(out)
}

/// Removes index `k` from `v`.
pub fn without<T: Clone>(v: &[T], k: usize) -> Vec<T> {
    v.iter().enumerate().filter(|&(i, _)| i != k).map(|(_, x)| x.clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{edges, joint, snapshot, Rng};

    /// Shrinks to a 1-minimal history: it still fails and no single step smaller does.
    fn minimal<H: Shrink + Clone + std::fmt::Display>(h: H, fails: impl Fn(&H) -> bool) -> H {
        let m = shrink(h, &fails);
        assert!(fails(&m));
        assert!(m.smaller().iter().all(|c| !fails(c)), "not minimal:\n{m}");
        m
    }

    /// A drop needs a demotion and a write it misses: two writes at most remain.
    #[test]
    fn joint_drop_shrinks_to_two_writes() {
        let mut rng = Rng(7);
        let h = std::iter::repeat_with(|| joint::random_hist(&mut rng)).find(|h| joint::walk(h).dropped != 0 && h.writes.len() >= 5).unwrap();
        let m = minimal(h, |c: &joint::JHist| joint::walk(c).dropped != 0);
        assert_eq!(m.writes.len(), 2, "{m}");
        assert!(m.writes.iter().all(|w| w.t <= 3) && m.writes.iter().all(|w| w.id <= 2), "{m}");
    }

    #[test]
    fn edges_drop_shrinks() {
        let mut rng = Rng(8);
        let h = std::iter::repeat_with(|| edges::random_hist(&mut rng)).find(|h| edges::walk(h).dropped != 0 && h.writes.len() >= 5).unwrap();
        let m = minimal(h, |c: &edges::EHist| edges::walk(c).dropped != 0);
        assert!(m.writes.len() <= 2, "{m}");
    }

    #[test]
    fn snapshot_drop_shrinks() {
        let mut rng = Rng(9);
        let h = std::iter::repeat_with(|| snapshot::random_hist(&mut rng)).find(|h| snapshot::walk(h).g.dropped != 0 && h.writes.len() >= 5).unwrap();
        let m = minimal(h, |c: &snapshot::SHist| snapshot::walk(c).g.dropped != 0);
        assert!(m.writes.len() <= 3, "{m}");
    }

    /// After every delivery every node agrees, in every model (§5: validity is a deterministic
    /// function of the held commits).
    #[test]
    fn quiescence() {
        let mut rng = Rng(10);
        for _ in 0..2000 {
            let h = joint::random_hist(&mut rng);
            assert_eq!(joint::quiescent(&h), Ok(()), "{h}");
            let h = edges::random_hist(&mut rng);
            assert_eq!(edges::quiescent(&h, edges::Drops::Sticky), Ok(()), "{h}");
            let h = snapshot::random_hist(&mut rng);
            assert_eq!(snapshot::quiescent(&h), Ok(()), "{h}");
        }
    }

    #[test]
    fn compaction_keeps_order() {
        let map = compact_times(&[0, 5, 9, 5, LATE]).unwrap();
        assert_eq!([0, 5, 9, LATE].map(&map), [0, 1, 2, LATE]);
        let map = compact_times(&[3, 7]).unwrap();
        assert_eq!([3, 7].map(&map), [1, 2]);
        assert!(compact_times(&[1, 2]).is_none());
        assert_eq!(compact_ids(&[40u32, 7, 9]), Some(vec![3, 1, 2]));
    }
}
