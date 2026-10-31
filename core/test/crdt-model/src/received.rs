//! Received-dot ranges per author source for one aspect, and the frontiers a snapshot carries (spec §8).
use crate::stamp::Source;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default)]
pub struct Received(BTreeMap<Source, Vec<(u64, u64)>>);

impl Received {
    /// Record counters `[lo, hi)` of `src` as applied.
    pub fn add(&mut self, src: &Source, lo: u64, hi: u64) {
        if lo >= hi {
            return;
        }
        let v = self.0.entry(src.clone()).or_default();
        v.push((lo, hi));
        v.sort();
        let mut out: Vec<(u64, u64)> = Vec::new();
        for (a, b) in v.drain(..) {
            match out.last_mut() {
                Some(l) if a <= l.1 => l.1 = l.1.max(b),
                _ => out.push((a, b)),
            }
        }
        *v = out;
    }
    /// Largest `ctr` with `[1, ctr]` applied, 0 if none.
    pub fn frontier(&self, src: &Source) -> u64 {
        match self.0.get(src).and_then(|v| v.first()) {
            Some((1, hi)) => hi - 1,
            _ => 0,
        }
    }
    /// Frontiers of every `Node` and `Session` source with at least counter 1 applied.
    pub fn frontiers(&self) -> Vec<(Source, u64)> {
        self.0.keys().filter(|s| matches!(s, Source::Node(_) | Source::Session(_))).map(|s| (s.clone(), self.frontier(s))).filter(|x| x.1 > 0).collect()
    }
    /// A snapshot's frontier closes `[1, ctr]`.
    pub fn add_frontiers(&mut self, fr: &[(Source, u64)]) {
        for (s, c) in fr {
            self.add(s, 1, c + 1);
        }
    }
}
