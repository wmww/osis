//! What a join did: whether the read may have changed, which writes died (spec/crdt.md §4.8),
//! and whether a death the state cannot date may have been met, so the node fires listeners and
//! tracks retention per body without re-reading the state.

use crate::stamp::{Dot, Stamp};
use osis_base::Ts;

/// A write superseded by the join: pruned by a reset, beaten as a register, case, flag or
/// position winner, or its element removed. `at` is the `ts` of the superseding write, `by` its
/// dot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Death {
    pub stamp: Stamp,
    pub at: Ts,
    pub by: Dot,
}

/// Change summary of one join.
#[derive(Clone, Debug, Default)]
pub struct Changes {
    changed: bool,
    deaths: Vec<Death>,
    undated: bool,
}

impl Changes {
    pub fn new() -> Changes {
        Changes::default()
    }
    /// The aspect's read may differ from before the join.
    pub fn is_changed(&self) -> bool {
        self.changed
    }
    pub fn deaths(&self) -> &[Death] {
        &self.deaths
    }
    pub fn into_deaths(self) -> Vec<Death> {
        self.deaths
    }
    /// A text element's write joined out of order or as a copy of one held (§5.7: a flag no
    /// newer than a held undelete, a creation under a flag), whose effect on deaths the state
    /// cannot show, so they are dated from the held bodies (spec/commits.md §5).
    pub fn undated(&self) -> bool {
        self.undated
    }
    /// Adds what another join did (a join done in pieces, spec/crdt.md §8).
    pub fn merge(&mut self, o: Changes) {
        self.changed |= o.changed;
        self.deaths.extend(o.deaths);
        self.undated |= o.undated;
    }
    /// Keeps the deaths `keep` accepts.
    pub fn retain_deaths(&mut self, keep: impl FnMut(&Death) -> bool) {
        self.deaths.retain(keep);
    }
    /// Records that a write landed whose death the state cannot date (`undated`).
    pub(crate) fn undatable(&mut self) {
        self.undated = true;
    }
    /// Records that a write landed or went, so the read may have changed.
    pub(crate) fn touch(&mut self) {
        self.changed = true;
    }
    /// `is_changed`, cleared.
    pub(crate) fn take_changed(&mut self) -> bool {
        std::mem::take(&mut self.changed)
    }
    /// Records deaths another join found without changing this one's read (`state::cross_deaths`).
    pub(crate) fn report(&mut self, deaths: Vec<Death>) {
        self.deaths.extend(deaths);
    }
    /// Records that the write stamped `stamp` died, superseded by the write stamped `by`.
    pub(crate) fn died(&mut self, stamp: &Stamp, by: &Stamp) {
        self.changed = true;
        self.deaths.push(Death { stamp: stamp.clone(), at: by.ts, by: by.dot.clone() });
    }
}
