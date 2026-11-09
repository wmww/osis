//! Keyed list steps (notes/fast-design.md): which rows of the stream, cards and rows blocks of a
//! node changed. Toolkit-free; `render` applies them through `list`, and a test reads them.

use super::{Block, Entry, Placed, Run};
use crate::list::{Op, reconcile};

/// For each block whose rows changed: its index and the steps on its rows.
pub type ListSteps = Vec<(usize, Vec<Op<String>>)>;

fn frame_eq(a: &Run, b: &Run) -> bool {
    a.cols == b.cols && a.new == b.new && a.reorder == b.reorder
}

/// Empty cards or rows without a "new" tile are no widget at all.
fn shown(r: &Run) -> bool {
    !r.entries.is_empty() || r.new.is_some()
}

fn rows(p: &[Entry]) -> Vec<(String, &Entry)> {
    p.iter().map(|e| (e.key.clone(), e)).collect()
}

/// The row steps from `old` to `new`, or `None` if something other than rows differs and the
/// node must be rebuilt.
pub fn steps(old: &[Block], new: &[Block]) -> Option<ListSteps> {
    if old.len() != new.len() {
        return None;
    }
    let mut out = Vec::new();
    for (i, (a, b)) in old.iter().zip(new).enumerate() {
        if a == b {
            continue;
        }
        let (x, y): (&[Entry], &[Entry]) = match (a, b) {
            (Block::Entries(Placed::Stream(x)), Block::Entries(Placed::Stream(y))) => (x, y),
            (Block::Entries(Placed::Cards(x)), Block::Entries(Placed::Cards(y))) | (Block::Entries(Placed::Rows(x)), Block::Entries(Placed::Rows(y))) if frame_eq(x, y) && shown(x) && shown(y) => (&x.entries, &y.entries),
            _ => return None,
        };
        out.push((i, reconcile(&rows(x), &rows(y))));
    }
    Some(out)
}
