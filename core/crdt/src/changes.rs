//! What a join did: whether the read may have changed, so the node fires listeners and writes
//! the state back. Which writes died is not reported: it is `Fragment::winners` before and
//! after (spec/crdt.md §4.8).

/// Change summary of one join.
#[derive(Clone, Debug, Default)]
pub struct Changes {
    changed: bool,
}

impl Changes {
    pub fn new() -> Changes {
        Changes::default()
    }
    /// The aspect's read may differ from before the join.
    pub fn is_changed(&self) -> bool {
        self.changed
    }
    /// Adds what another join did (a join done in pieces, spec/crdt.md §8).
    pub fn merge(&mut self, o: Changes) {
        self.changed |= o.changed;
    }
    /// Records that a write landed or went, so the read may have changed.
    pub(crate) fn touch(&mut self) {
        self.changed = true;
    }
    /// `is_changed`, cleared.
    pub(crate) fn take_changed(&mut self) -> bool {
        std::mem::take(&mut self.changed)
    }
}
