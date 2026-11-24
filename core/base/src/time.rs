//! Time types and the `Clock` plug (spec/crdt.md §2.2). The HLC itself lives in the node.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// A moment: milliseconds since the Unix epoch, UTC.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Time(pub u64);

/// `Time` by its older name, which the layers below the API still use.
pub use self::Time as WallMs;

impl Time {
    pub fn saturating_add(self, ms: u64) -> Time {
        Time(self.0.saturating_add(ms))
    }
}

/// A reading of a node's monotonic clock: ms from an origin of its own, never going back and
/// running as time passes whatever the wall clock does (spec/sync-streams.md §1 Waits). Every wait
/// a node keeps in memory runs on it; it is never stamped, stored or compared with a wall time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Mono(pub u64);

impl Mono {
    /// `ms` later.
    pub fn after(self, ms: u64) -> Mono {
        Mono(self.0.saturating_add(ms))
    }
}

/// Hybrid timestamp: `wall_ms * 2^16 + logical`, `wall_ms < 2^47`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Ts(u64);

impl Ts {
    pub const ZERO: Ts = Ts(0);
    /// The greatest valid `Ts`.
    pub const MAX: Ts = Ts((Ts::WALL_LIMIT << 16) - 1);
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

/// Clock source, injected so tests and the simulator control time: the wall clock, which may
/// jump either way, and a monotonic one (`Mono`).
pub trait Clock: Send + Sync {
    fn now_wall_ms(&self) -> WallMs;
    fn mono(&self) -> Mono;
}

/// Test clock: its wall clock reads what it was set to; its monotonic clock starts at the same
/// reading and moves with every move forward (`set` back leaves it).
#[derive(Debug, Default)]
pub struct ManualClock {
    wall: AtomicU64,
    mono: AtomicU64,
}

impl ManualClock {
    pub fn new(start: WallMs) -> ManualClock {
        ManualClock { wall: AtomicU64::new(start.0), mono: AtomicU64::new(start.0) }
    }
    pub fn set(&self, t: WallMs) {
        let was = self.wall.swap(t.0, Ordering::SeqCst);
        add(&self.mono, t.0.saturating_sub(was));
    }
    pub fn advance(&self, ms: u64) {
        add(&self.wall, ms);
        add(&self.mono, ms);
    }
}

/// Saturating add by CAS loop (`fetch_update` is deprecated past the MSRV's replacement).
fn add(x: &AtomicU64, ms: u64) {
    let mut cur = x.load(Ordering::SeqCst);
    while let Err(seen) = x.compare_exchange_weak(cur, cur.saturating_add(ms), Ordering::SeqCst, Ordering::SeqCst) {
        cur = seen;
    }
}

impl Clock for ManualClock {
    fn now_wall_ms(&self) -> WallMs {
        WallMs(self.wall.load(Ordering::SeqCst))
    }
    fn mono(&self) -> Mono {
        Mono(self.mono.load(Ordering::SeqCst))
    }
}

/// The system clock (drivers only; libraries take a `&dyn Clock`). Its monotonic clock is
/// `Instant`'s, from the first reading in the process.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_wall_ms(&self) -> WallMs {
        let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        WallMs(u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }
    fn mono(&self) -> Mono {
        static ORIGIN: OnceLock<Instant> = OnceLock::new();
        Mono(u64::try_from(ORIGIN.get_or_init(Instant::now).elapsed().as_millis()).unwrap_or(u64::MAX))
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
}
