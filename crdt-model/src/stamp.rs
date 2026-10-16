//! Sources, dots, timestamps, stamps (spec §2).
use std::cmp::Ordering;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Source {
    Node([u8; 15]),
    Commit([u8; 32]),
    /// Synthetic source produced by lattice embeddings (spec §7); belongs to the author of the dot.
    Derived(Box<Dot>),
}

impl Source {
    fn rank(&self) -> u8 {
        match self {
            Source::Node(_) => 0,
            Source::Commit(_) => 1,
            Source::Derived(_) => 2,
        }
    }
    /// Who authored writes under this source.
    pub fn author(&self) -> &Source {
        match self {
            Source::Derived(d) => d.source.author(),
            s => s,
        }
    }
    /// Test helper: node source from a small number.
    pub fn node(n: u8) -> Source {
        let mut b = [0u8; 15];
        b[14] = n;
        Source::Node(b)
    }
}

impl Ord for Source {
    fn cmp(&self, o: &Self) -> Ordering {
        self.rank().cmp(&o.rank()).then_with(|| match (self, o) {
            (Source::Node(a), Source::Node(b)) => a.cmp(b),
            (Source::Commit(a), Source::Commit(b)) => a.cmp(b),
            (Source::Derived(a), Source::Derived(b)) => a.cmp(b),
            _ => unreachable!(),
        })
    }
}
impl PartialOrd for Source {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Dot {
    pub source: Source,
    pub ctr: u64,
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
