//! Time types and the `Clock` plug (spec/crdt.md §2.2). The HLC itself lives in the node.

use std::sync::atomic::{AtomicU64, Ordering};

/// Milliseconds since the Unix epoch, UTC.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct WallMs(pub u64);

impl WallMs {
    pub fn saturating_add(self, ms: u64) -> WallMs {
        WallMs(self.0.saturating_add(ms))
    }
}

/// Hybrid timestamp: `wall_ms * 2^16 + logical`, `wall_ms < 2^47`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Ts(u64);

impl Ts {
    /// Exclusive bound on `wall_ms`.
    pub const WALL_LIMIT: u64 = 1 << 47;
    /// `None` if `wall_ms >= 2^47` or `logical >= 2^16`.
    pub fn make(wall: WallMs, logical: u64) -> Option<Ts> {
        if wall.0 < Self::WALL_LIMIT && logical <= 0xffff { Some(Ts((wall.0 << 16) | logical)) } else { None }
    }
    /// From the integer on the wire; `None` if `wall_ms` is out of range.
    pub fn from_u64(n: u64) -> Option<Ts> {
        if n >> 16 < Self::WALL_LIMIT { Some(Ts(n)) } else { None }
    }
    pub fn to_u64(self) -> u64 {
        self.0
    }
    pub fn wall_ms(self) -> WallMs {
        WallMs(self.0 >> 16)
    }
    pub fn logical(self) -> u64 {
        self.0 & 0xffff
    }
}

/// Wall-clock source, injected so tests and the simulator control time.
pub trait Clock: Send + Sync {
    fn now_wall_ms(&self) -> WallMs;
}

/// Test clock: returns what it was set to.
#[derive(Debug, Default)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    pub fn new(start: WallMs) -> ManualClock {
        ManualClock(AtomicU64::new(start.0))
    }
    pub fn set(&self, t: WallMs) {
        self.0.store(t.0, Ordering::SeqCst);
    }
    pub fn advance(&self, ms: u64) {
        // fetch_update with saturation; never fails since the closure always returns Some.
        let _ = self.0.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |t| Some(t.saturating_add(ms)));
    }
}

impl Clock for ManualClock {
    fn now_wall_ms(&self) -> WallMs {
        WallMs(self.0.load(Ordering::SeqCst))
    }
}

/// The system clock (drivers only; libraries take a `&dyn Clock`).
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_wall_ms(&self) -> WallMs {
        let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        WallMs(u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec/crdt.md §2.2: ts = wall_ms * 2^16 + logical, wall_ms < 2^47.
    #[test]
    fn ts_layout() {
        let t = Ts::make(WallMs(5), 3).unwrap();
        assert_eq!(t.to_u64(), 5 * 65536 + 3);
        assert_eq!((t.wall_ms(), t.logical()), (WallMs(5), 3));
        assert!(Ts::make(WallMs(1 << 47), 0).is_none());
        assert!(Ts::make(WallMs(0), 1 << 16).is_none());
        assert!(Ts::from_u64(u64::MAX).is_none());
        assert_eq!(Ts::from_u64((1 << 63) - 1).map(Ts::wall_ms), Some(WallMs((1 << 47) - 1)));
        assert!(Ts::make(WallMs(1), 0).unwrap() > Ts::make(WallMs(0), 0xffff).unwrap());
    }

    #[test]
    fn manual_clock() {
        let c = ManualClock::new(WallMs(10));
        c.advance(5);
        assert_eq!(c.now_wall_ms(), WallMs(15));
        c.set(WallMs(3));
        assert_eq!(c.now_wall_ms(), WallMs(3));
        c.advance(u64::MAX);
        assert_eq!(c.now_wall_ms(), WallMs(u64::MAX));
        assert!(SystemClock.now_wall_ms() > WallMs(1_600_000_000_000));
    }
}
