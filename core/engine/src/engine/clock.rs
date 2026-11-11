//! The HLC (spec/crdt.md §2.2) over the node's wall clock: `max(wall clock, last ts seen)`,
//! `logical` incremented on equal `wall_ms`. A writer that exhausts the
//! 16 logical bits within one millisecond moves to the next millisecond instead of waiting.

use osis_base::{Clock, Ts, WallMs};
use std::sync::Arc;

pub struct Hlc {
    clock: Arc<dyn Clock>,
    last: Ts,
}

impl Hlc {
    pub fn new(clock: Arc<dyn Clock>, last: Ts) -> Hlc {
        Hlc { clock, last }
    }

    /// The wall clock.
    pub fn wall(&self) -> WallMs {
        self.clock.now_wall_ms()
    }

    pub fn last(&self) -> Ts {
        self.last
    }

    /// A fresh `ts` for a local commit, above every `ts` seen.
    pub fn next(&mut self) -> Ts {
        let ts = self.peek();
        self.last = ts;
        ts
    }

    /// The `ts` `next` would give now.
    pub fn peek(&self) -> Ts {
        let w = self.wall();
        let l = self.last;
        let ts = if w > l.wall_ms() {
            Ts::make(w, 0)
        } else if l.logical() < 0xffff {
            Ts::make(l.wall_ms(), l.logical() + 1)
        } else {
            Ts::make(l.wall_ms().saturating_add(1), 0)
        };
        // Beyond 2^47 ms (year 6429) the clock stops advancing.
        ts.unwrap_or(l)
    }

    /// A received commit's `ts` (not parked) advances the clock.
    pub fn observe(&mut self, ts: Ts) {
        if ts > self.last {
            self.last = ts;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osis_base::ManualClock;

    // spec/crdt.md §2.2: ts = max(wall, last seen), logical incremented on equal wall_ms.
    #[test]
    fn hlc_rules_spec_2_2() {
        let c = Arc::new(ManualClock::new(WallMs(1000)));
        let mut h = Hlc::new(c.clone(), Ts::default());
        let a = h.next();
        assert_eq!((a.wall_ms(), a.logical()), (WallMs(1000), 0));
        let b = h.next();
        assert_eq!((b.wall_ms(), b.logical()), (WallMs(1000), 1));
        h.observe(Ts::make(WallMs(5000), 7).unwrap());
        let d = h.next();
        assert_eq!((d.wall_ms(), d.logical()), (WallMs(5000), 8));
        c.set(WallMs(6000));
        assert_eq!(h.next(), Ts::make(WallMs(6000), 0).unwrap());
    }

    // spec/crdt.md §2.2: 16 logical bits; exhausting them moves to the next millisecond.
    #[test]
    fn hlc_logical_exhaustion_spec_2_2() {
        let c = Arc::new(ManualClock::new(WallMs(1000)));
        let mut h = Hlc::new(c, Ts::make(WallMs(1000), 0xffff).unwrap());
        assert_eq!(h.next(), Ts::make(WallMs(1001), 0).unwrap());
    }
}
