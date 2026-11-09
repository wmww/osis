//! Which commit a write belongs to (spec §2.4, §4.7 Attribution): per source, the counter ranges the headers give.
//! A commit-form commit owns every counter of its own source; a session-form one the range its header gives per
//! aspect, so one map serves one aspect.
use crate::stamp::{Dot, Source};
use crate::state::origin;
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct Origins<C>(BTreeMap<Source, Vec<(u64, u64, C)>>);

impl<C> Default for Origins<C> {
    fn default() -> Self {
        Origins(BTreeMap::new())
    }
}

impl<C> Origins<C> {
    /// Counters `[lo, hi)` of `src` belong to commit `c`.
    pub fn add(&mut self, src: Source, lo: u64, hi: u64, c: C) {
        self.0.entry(src).or_default().push((lo, hi, c));
    }
    /// A commit-form commit `c` with ID `id`: every counter of its source.
    pub fn commit_form(&mut self, id: [u8; 32], c: C) {
        self.add(Source::Commit(id), 0, u64::MAX, c);
    }
    /// The commit a write under dot `d` belongs to (a `Derived` dot: its underlying dot's); none for a dot no
    /// header named.
    pub fn of(&self, d: &Dot) -> Option<&C> {
        let d = origin(d);
        self.0.get(&d.source)?.iter().find(|x| x.0 <= d.ctr && d.ctr < x.1).map(|x| &x.2)
    }
}
