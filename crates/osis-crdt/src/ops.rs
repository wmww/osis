//! Local ops producing deltas (spec/crdt.md §4.5, §5): the counter allocator.

use crate::stamp::{CounterRange, Source, Stamp};
use osis_core::Ts;

/// One writer's counters for one aspect's delta in one commit (§2.3). Commit-level writes share
/// the delta stamp `(ts, source, lo)`; creations and position writes take `lo, lo+1, ..` in op
/// order. The delta consumes `[lo, max(lo + 1, last + 1))`.
///
/// A commit-form writer does not know its commit ID before signing; it writes with a placeholder
/// source and the delta is re-read with the real one (own dots are `Src` 0 on the wire, §3.2).
#[derive(Clone, Debug)]
pub struct Writer {
    ts: Ts,
    src: Source,
    lo: u64,
    next: u64,
}

impl Writer {
    /// `lo` is the first unused counter of `src` for this aspect (≥ 1).
    pub fn new(ts: Ts, src: Source, lo: u64) -> Writer {
        let lo = lo.max(1);
        Writer { ts, src, lo, next: lo }
    }
    pub fn ts(&self) -> Ts {
        self.ts
    }
    pub fn source(&self) -> &Source {
        &self.src
    }
    /// Stamp of every commit-level write (register values, resets, flags, case, `W`).
    pub fn delta_stamp(&self) -> Stamp {
        Stamp::new(self.ts, self.src.clone(), self.lo)
    }
    /// A fresh counter for an element creation or position write.
    pub fn fresh(&mut self) -> Stamp {
        let s = Stamp::new(self.ts, self.src.clone(), self.next);
        self.next = self.next.saturating_add(1);
        s
    }
    /// The range this delta consumes so far.
    pub fn range(&self) -> CounterRange {
        CounterRange { lo: self.lo, hi: self.next.max(self.lo.saturating_add(1)) }
    }
}
