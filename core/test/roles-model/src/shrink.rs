//! Shrinking a failing world: its moves less one.

/// Removes index `k` from `v`.
pub fn without<T: Clone>(v: &[T], k: usize) -> Vec<T> {
    v.iter().enumerate().filter(|&(i, _)| i != k).map(|(_, x)| x.clone()).collect()
}
