//! Move resolution (spec/permissions.md §7): read-time resolution of a tid held in a value of
//! thing R through `/was` claims with standing, else `/moved`, at most `RESOLUTION_HOPS` hops.

use crate::timeline::{At, Timeline};
use osis_core::Tid;

/// `RESOLUTION_HOPS` (spec/wire.md §2).
pub const RESOLUTION_HOPS: usize = 8;

/// What the node holds of `/was` and `/moved` (valid reads, §5.2).
pub trait MoveIndex {
    /// Held things M whose `/was` reads `t`.
    fn continued_by(&self, t: &Tid) -> Vec<Tid>;
    /// `/moved` of `t`, if the node holds `t` and it names one.
    fn moved(&self, t: &Tid) -> Option<Tid>;
}

impl Timeline {
    /// §7: does R's owner chain hold rights in M? An actor of R's owner chain is in M's owner
    /// chain, or holds an edge on M or on an actor of M's owner chain. Readings: owner chains
    /// are transitive; R itself is not part of its owner chain.
    pub fn has_standing(&self, r: &Tid, m: &Tid, at: At) -> bool {
        let (r_up, r_top) = self.owners().chain(r);
        let (mut m_chain, m_top) = self.owners().chain(m);
        m_chain.extend(m_top);
        let edges = self.edges_at(at.point);
        r_up.iter().chain(r_top.iter()).any(|c| {
            m_chain.contains(c) || std::iter::once(m).chain(m_chain.iter()).any(|y| edges.get(c, y).is_some_and(|e| e.alive_at(at.ts)))
        })
    }

    /// §7: resolves tid `t` held in a value of thing `r`: the one held M with `/was = t` in
    /// which R's owner chain has standing, else `t`'s `/moved`, repeated from the result.
    pub fn resolve(&self, index: &dyn MoveIndex, r: &Tid, t: &Tid, at: At) -> Tid {
        let mut cur = *t;
        for _ in 0..RESOLUTION_HOPS {
            let mut claims: Vec<Tid> = index.continued_by(&cur).into_iter().filter(|m| self.has_standing(r, m, at)).collect();
            claims.sort();
            claims.dedup();
            cur = match (claims.as_slice(), index.moved(&cur)) {
                ([m], _) => *m,
                (_, Some(x)) => x,
                _ => return cur,
            };
        }
        cur
    }
}
