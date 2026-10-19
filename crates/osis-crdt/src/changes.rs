//! What a join did: whether the read may have changed and which writes died (spec/crdt.md §4.8),
//! so the node fires listeners and tracks retention per body without re-reading the state.

use crate::stamp::Stamp;
use osis_core::Ts;

/// A write superseded by the join: pruned by a reset, beaten as a register, case, flag or
/// position winner, or its element removed. `at` is the `ts` of the superseding write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Death {
    pub stamp: Stamp,
    pub at: Ts,
}

/// Change summary of one join.
#[derive(Clone, Debug, Default)]
pub struct Changes {
    changed: bool,
    deaths: Vec<Death>,
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
    /// Records that a write landed or went, so the read may have changed.
    pub(crate) fn touch(&mut self) {
        self.changed = true;
    }
    /// Records that the write stamped `stamp` died at `at`.
    pub(crate) fn died(&mut self, stamp: &Stamp, at: Ts) {
        self.changed = true;
        self.deaths.push(Death { stamp: stamp.clone(), at });
    }
}
