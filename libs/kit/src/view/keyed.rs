//! Keyed list steps (notes/fast-design.md): which rows of a node's lists changed. Toolkit-free;
//! `render` applies them through `list`, and a test reads them.

use super::Block;
use super::paged::ListRow;
use crate::list::{Op, reconcile};

/// For each block whose rows changed: its index and the steps on its rows.
pub type ListSteps = Vec<(usize, Vec<Op<String>>)>;

fn rows(p: &[ListRow]) -> Vec<(String, &ListRow)> {
    p.iter().map(|e| (e.key.clone(), e)).collect()
}

/// The row steps from `old` to `new`, or `None` if something other than rows differs and the
/// node must be rebuilt. The rows are a window, so this is bounded by the window whatever the
/// size of the list.
pub fn steps(old: &[Block], new: &[Block]) -> Option<ListSteps> {
    if old.len() != new.len() {
        return None;
    }
    let mut out = Vec::new();
    for (i, (a, b)) in old.iter().zip(new).enumerate() {
        if a == b {
            continue;
        }
        let (Block::List(x), Block::List(y)) = (a, b) else { return None };
        if !x.frame_eq(y) || x.is_empty() || y.is_empty() {
            return None;
        }
        out.push((i, reconcile(&rows(&x.rows), &rows(&y.rows))));
    }
    Some(out)
}
