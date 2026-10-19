//! Sources, dots, stamps and their total order; counter ranges; source interning (spec/crdt.md §2).

use osis_core::{CommitId, Tid, Ts};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

/// Who minted a run of counters (§2.1).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SourceKind {
    /// A node's signing identity.
    Node(Tid),
    /// A commit-form commit.
    Commit(CommitId),
    /// Synthetic source of an embedding (§7); the dot's source is never `Derived`.
    Derived(Dot),
}

impl SourceKind {
    fn rank(&self) -> u8 {
        match self {
            SourceKind::Node(_) => 0,
            SourceKind::Commit(_) => 1,
            SourceKind::Derived(_) => 2,
        }
    }
}

/// §2.2: kind (`Node` < `Commit` < `Derived`), then bytes (`Derived`: the underlying dot).
impl Ord for SourceKind {
    fn cmp(&self, o: &Self) -> Ordering {
        match (self, o) {
            (SourceKind::Node(a), SourceKind::Node(b)) => a.cmp(b),
            (SourceKind::Commit(a), SourceKind::Commit(b)) => a.cmp(b),
            (SourceKind::Derived(a), SourceKind::Derived(b)) => a.cmp(b),
            _ => self.rank().cmp(&o.rank()),
        }
    }
}
impl PartialOrd for SourceKind {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

/// A shared, cheaply cloned source: a state holds a pointer per write, not 15 or 32 bytes. Equal
/// sources from one `Interner` share the allocation; equality and order never depend on sharing.
#[derive(Clone)]
pub struct Source(Arc<SourceKind>);

impl Source {
    pub fn node(tid: Tid) -> Source {
        Source(Arc::new(SourceKind::Node(tid)))
    }
    pub fn commit(id: CommitId) -> Source {
        Source(Arc::new(SourceKind::Commit(id)))
    }
    /// `None` if `dot`'s source is itself `Derived` (§3.2: Derived of a Node or Commit dot only).
    pub fn derived(dot: Dot) -> Option<Source> {
        if dot.src.is_derived() {
            return None;
        }
        Some(Source(Arc::new(SourceKind::Derived(dot))))
    }
    pub fn kind(&self) -> &SourceKind {
        &self.0
    }
    pub fn is_derived(&self) -> bool {
        matches!(*self.0, SourceKind::Derived(_))
    }
    /// The source that authored writes under this one: a `Derived` source belongs to the author
    /// of its underlying dot (§2.1).
    pub fn author(&self) -> &Source {
        match &*self.0 {
            SourceKind::Derived(d) => &d.src,
            _ => self,
        }
    }
    pub fn as_node(&self) -> Option<Tid> {
        match &*self.0 {
            SourceKind::Node(t) => Some(*t),
            _ => None,
        }
    }
}

impl PartialEq for Source {
    fn eq(&self, o: &Self) -> bool {
        Arc::ptr_eq(&self.0, &o.0) || self.0 == o.0
    }
}
impl Eq for Source {}
impl Hash for Source {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.0.hash(h)
    }
}
impl Ord for Source {
    fn cmp(&self, o: &Self) -> Ordering {
        if Arc::ptr_eq(&self.0, &o.0) {
            return Ordering::Equal;
        }
        self.0.cmp(&o.0)
    }
}
impl PartialOrd for Source {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
impl fmt::Debug for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &*self.0 {
            SourceKind::Node(t) => write!(f, "N{t:?}"),
            SourceKind::Commit(c) => write!(f, "C{c:?}"),
            SourceKind::Derived(d) => write!(f, "D({d:?})"),
        }
    }
}

/// Deduplicates sources so a state holds one allocation per distinct source.
#[derive(Default)]
pub struct Interner(HashMap<SourceKind, Source>);

impl Interner {
    pub fn new() -> Interner {
        Interner::default()
    }
    /// The shared copy of `s`.
    pub fn intern(&mut self, s: &Source) -> Source {
        self.0.entry(s.kind().clone()).or_insert_with(|| s.clone()).clone()
    }
    pub fn node(&mut self, tid: Tid) -> Source {
        self.intern(&Source::node(tid))
    }
    pub fn commit(&mut self, id: CommitId) -> Source {
        self.intern(&Source::commit(id))
    }
}

/// `(source, counter)`, counter ≥ 1: one write forever, and the identity of the element it
/// created (§2.1). Ordered by source, then counter.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Dot {
    pub src: Source,
    pub ctr: u64,
}

impl Dot {
    pub fn new(src: Source, ctr: u64) -> Dot {
        Dot { src, ctr }
    }
    /// The non-`Derived` dot whose delta owns writes under this one (§4.7).
    pub fn owner(&self) -> &Dot {
        match self.src.kind() {
            SourceKind::Derived(d) => d,
            _ => self,
        }
    }
}
impl fmt::Debug for Dot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}:{}", self.src, self.ctr)
    }
}

/// `(ts, dot)` with the total order of §2.2: `ts`, then the dot. Distinct writes compare equal
/// only when they share a commit's delta stamp (§2.3).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Stamp {
    pub ts: Ts,
    pub dot: Dot,
}

impl Stamp {
    pub fn new(ts: Ts, src: Source, ctr: u64) -> Stamp {
        Stamp { ts, dot: Dot { src, ctr } }
    }
}
impl fmt::Debug for Stamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {:?})", self.ts.to_u64(), self.dot)
    }
}

/// The counter range `[lo, hi)` a delta consumes from its writer's source (§2.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CounterRange {
    pub lo: u64,
    pub hi: u64,
}

impl CounterRange {
    /// Range of snapshot and import commits, which consume no counters (§2.4).
    pub const EMPTY: CounterRange = CounterRange { lo: 1, hi: 1 };
    pub fn contains(&self, ctr: u64) -> bool {
        self.lo <= ctr && ctr < self.hi
    }
    pub fn is_empty(&self) -> bool {
        self.hi <= self.lo
    }
}

/// `max` of two optional stamps (`None` is −∞).
pub(crate) fn max_opt(a: Option<Stamp>, b: Option<Stamp>) -> Option<Stamp> {
    match (a, b) {
        (None, x) | (x, None) => x,
        (Some(a), Some(b)) => Some(if a >= b { a } else { b }),
    }
}

/// A write with stamp `s` survives effective reset `e` iff `s >= e` (§4.2). For sequences.
#[allow(dead_code)]
pub(crate) fn survives(s: &Stamp, e: Option<&Stamp>) -> bool {
    e.is_none_or(|e| s >= e)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tid(n: u8) -> Tid {
        let mut b = [0u8; 15];
        b[14] = n;
        Tid::from_bytes(b)
    }
    fn ts(n: u64) -> Ts {
        Ts::from_u64(n).unwrap()
    }

    #[test]
    fn stamp_order_spec_2_2() {
        let n1 = Source::node(tid(1));
        let n2 = Source::node(tid(2));
        let c = Source::commit(CommitId([0; 32]));
        let d = Source::derived(Dot::new(n1.clone(), 1)).unwrap();
        // ts first
        assert!(Stamp::new(ts(1), d.clone(), 9) < Stamp::new(ts(2), n1.clone(), 1));
        // then kind: Node < Commit < Derived
        assert!(Stamp::new(ts(1), n2.clone(), 9) < Stamp::new(ts(1), c.clone(), 1));
        assert!(Stamp::new(ts(1), c.clone(), 9) < Stamp::new(ts(1), d.clone(), 1));
        // then source bytes, then counter
        assert!(Stamp::new(ts(1), n1.clone(), 9) < Stamp::new(ts(1), n2.clone(), 1));
        assert!(Stamp::new(ts(1), n1.clone(), 1) < Stamp::new(ts(1), n1.clone(), 2));
        // Derived by the underlying dot
        let d2 = Source::derived(Dot::new(n1.clone(), 2)).unwrap();
        assert!(d < d2);
        assert!(Source::derived(Dot::new(d, 1)).is_none());
    }

    #[test]
    fn interner_shares_spec_2_1() {
        let mut i = Interner::new();
        let a = i.node(tid(3));
        let b = i.intern(&Source::node(tid(3)));
        assert!(Arc::ptr_eq(&a.0, &b.0));
        assert_eq!(a, Source::node(tid(3)));
        assert_eq!(Source::derived(Dot::new(a.clone(), 4)).unwrap().author(), &a);
    }

    #[test]
    fn counter_range_spec_2_3() {
        let r = CounterRange { lo: 3, hi: 5 };
        assert!(!r.contains(2) && r.contains(3) && r.contains(4) && !r.contains(5));
        assert!(CounterRange::EMPTY.is_empty());
    }
}
