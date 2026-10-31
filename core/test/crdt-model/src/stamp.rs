//! Sources, dots, timestamps, stamps (spec §2).
use std::cmp::Ordering;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Source {
    Node([u8; 15]),
    /// A node's in-memory session: tid then 16-byte nonce (spec §2.1).
    Session([u8; 31]),
    Commit([u8; 32]),
    /// Synthetic source produced by lattice embeddings (spec §7); belongs to the author of the dot.
    Derived(Box<Dot>),
}

impl Source {
    fn rank(&self) -> u8 {
        match self {
            Source::Node(_) => 0,
            Source::Session(_) => 1,
            Source::Commit(_) => 2,
            Source::Derived(_) => 3,
        }
    }
    /// Who authored writes under this source.
    pub fn author(&self) -> &Source {
        match self {
            Source::Derived(d) => d.source.author(),
            s => s,
        }
    }
    /// Test helper: session `nonce` of node `n` (a small number).
    pub fn session(n: u8, nonce: u8) -> Source {
        let mut b = [nonce; 31];
        b[..15].fill(0);
        b[14] = n;
        Source::Session(b)
    }
    /// Test helper: node source from a small number.
    pub fn node(n: u8) -> Source {
        let mut b = [0u8; 15];
        b[14] = n;
        Source::Node(b)
    }
}

/// Order of sources that are not `Derived`: `Node` < `Session` < `Commit`, then bytes (spec §2.2).
pub fn base_cmp(a: &Source, b: &Source) -> Ordering {
    match (a, b) {
        (Source::Node(x), Source::Node(y)) => x.cmp(y),
        (Source::Session(x), Source::Session(y)) => x.cmp(y),
        (Source::Commit(x), Source::Commit(y)) => x.cmp(y),
        _ => a.rank().cmp(&b.rank()),
    }
}

/// Dot order (spec §2.2) over an order of non-`Derived` sources: `(Derived(d), i)` orders as the sequence
/// `(d.source, d.ctr, i)`, any other dot as `(source, ctr)`: an embedded write sorts right after the write it embeds.
pub fn dot_cmp(a: &Dot, b: &Dot, base: &dyn Fn(&Source, &Source) -> Ordering) -> Ordering {
    let split = |d: &Dot| -> (Dot, Option<u64>) {
        match &d.source {
            Source::Derived(x) => ((**x).clone(), Some(d.ctr)),
            _ => (d.clone(), None),
        }
    };
    let ((x, i), (y, j)) = (split(a), split(b));
    base(&x.source, &y.source).then(x.ctr.cmp(&y.ctr)).then(i.cmp(&j))
}

/// Sources as prefixes of the dot order.
impl Ord for Source {
    fn cmp(&self, o: &Self) -> Ordering {
        let split = |s: &Source| -> (Source, Option<u64>) {
            match s {
                Source::Derived(d) => (d.source.clone(), Some(d.ctr)),
                _ => (s.clone(), None),
            }
        };
        let ((x, i), (y, j)) = (split(self), split(o));
        base_cmp(&x, &y).then(i.cmp(&j))
    }
}
impl PartialOrd for Source {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Dot {
    pub source: Source,
    pub ctr: u64,
}
impl Ord for Dot {
    fn cmp(&self, o: &Self) -> Ordering {
        dot_cmp(self, o, &base_cmp)
    }
}
impl PartialOrd for Dot {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

/// `wall_ms * 2^16 + logical` (spec §2.2).
pub type Ts = u64;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Stamp {
    pub ts: Ts,
    pub dot: Dot,
}

impl Stamp {
    pub fn new(ts: Ts, source: Source, ctr: u64) -> Stamp {
        Stamp { ts, dot: Dot { source, ctr } }
    }
}

/// `max` of two optional stamps.
pub fn max_opt(a: Option<Stamp>, b: Option<Stamp>) -> Option<Stamp> {
    match (a, b) {
        (None, x) | (x, None) => x,
        (Some(a), Some(b)) => Some(if a >= b { a } else { b }),
    }
}

/// A write with stamp `s` survives an effective reset `e` iff `s >= e` (spec §4.2).
pub fn survives(s: &Stamp, e: Option<&Stamp>) -> bool {
    match e {
        None => true,
        Some(e) => s >= e,
    }
}
