//! Relay-only uploads at a server or a member peer serving a label (spec/sync.md §5): admitted
//! by prefix expiry and size, counted against a per-label rate, and pushed once per blob within
//! its expiry window (a repeat is answered OK and pushed to nobody).

use crate::msg::Code;
use osis_base::format::{MAX_DRIFT_MS, MAX_RELAY_BLOB};
use osis_base::{BlobId, LabelId};
use std::collections::{BTreeSet, HashMap, HashSet};

/// What becomes of a relay-only upload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayVerdict {
    /// New: push it to the label's subscribers.
    Push,
    /// Relayed already within its window: answered OK, pushed to nobody.
    Seen,
    Refused(Code),
}

/// Per-label relay rate (spec/sync.md §5 rate limits). Resource bound: each relay is pushed to
/// every subscriber of the label (0: no signals; infinity: a writer or a replayer of stamped
/// blobs sends traffic at line rate times subscribers).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayLimits {
    /// Relays per label and window.
    pub count: u32,
    /// Relayed bytes per label and window.
    pub bytes: u64,
    pub window_ms: u64,
}

impl Default for RelayLimits {
    fn default() -> RelayLimits {
        RelayLimits { count: 6_000, bytes: 32 << 20, window_ms: 60_000 }
    }
}

/// Relayed (label, blob) pairs remembered until their prefix expiry, node-wide. Resource bound:
/// past it the earliest-expiring pair is forgotten, so a replay of that blob is pushed again
/// (minor: counted against its label's rate, and receivers drop what they delivered); 0: every
/// replay within the window is pushed; infinity: memory grows with every relay of the last two
/// hours. Each pair costs about 200 bytes (a hash-set and a B-tree entry): 13 MiB at the bound.
pub const MAX_RELAY_SEEN: usize = 1 << 16;

/// The relay state of one server or member peer (in memory; a restart forgets it).
#[derive(Clone, Debug)]
pub struct RelayGate {
    pub limits: RelayLimits,
    seen: HashSet<(LabelId, BlobId)>,
    by_expiry: BTreeSet<(u64, LabelId, BlobId)>,
    window: u64,
    used: HashMap<LabelId, (u32, u64)>,
}

impl Default for RelayGate {
    fn default() -> RelayGate {
        RelayGate::new(RelayLimits::default())
    }
}

impl RelayGate {
    pub fn new(limits: RelayLimits) -> RelayGate {
        RelayGate { limits, seen: HashSet::new(), by_expiry: BTreeSet::new(), window: 0, used: HashMap::new() }
    }

    /// Admits a stamped relay-only blob of `size` bytes with prefix expiry `expiry` at wall
    /// `now` (spec/sync.md §5): too large, without an expiry, expired or expiring more than
    /// `2 × MAX_DRIFT` ahead (a writer's `ts` at most `MAX_DRIFT` ahead, plus its window) is
    /// refused; a repeat within its window is `Seen`; past the label's rate, code 4.
    pub fn admit(&mut self, label: &LabelId, blob_id: &BlobId, size: usize, expiry: Option<u64>, now: u64) -> RelayVerdict {
        if size > MAX_RELAY_BLOB {
            return RelayVerdict::Refused(Code::TOO_LARGE);
        }
        let Some(t) = expiry else { return RelayVerdict::Refused(Code::REFUSED) };
        if t <= now {
            return RelayVerdict::Refused(Code::EXPIRED);
        }
        if t > now.saturating_add(2 * MAX_DRIFT_MS) {
            return RelayVerdict::Refused(Code::REFUSED);
        }
        while let Some(first) = self.by_expiry.first().copied()
            && first.0 <= now
        {
            self.by_expiry.pop_first();
            self.seen.remove(&(first.1, first.2));
        }
        if self.seen.contains(&(*label, *blob_id)) {
            return RelayVerdict::Seen;
        }
        let w = now / self.limits.window_ms.max(1);
        if w != self.window {
            self.window = w;
            self.used.clear();
        }
        let used = self.used.entry(*label).or_insert((0, 0));
        if used.0 >= self.limits.count || used.1.saturating_add(size as u64) > self.limits.bytes {
            return RelayVerdict::Refused(Code::RATE_LIMITED);
        }
        used.0 += 1;
        used.1 = used.1.saturating_add(size as u64);
        self.seen.insert((*label, *blob_id));
        self.by_expiry.insert((t, *label, *blob_id));
        if self.seen.len() > MAX_RELAY_SEEN
            && let Some(first) = self.by_expiry.pop_first()
        {
            self.seen.remove(&(first.1, first.2));
        }
        RelayVerdict::Push
    }

    /// Pairs remembered (tests).
    pub fn remembered(&self) -> usize {
        self.seen.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000_000_000;

    fn id(n: u32) -> BlobId {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&n.to_le_bytes());
        BlobId(b)
    }

    // spec/sync.md §5 (relay-only uploads): a replay within the window is pushed once; expiry,
    // size and rate bound what one replayer can make a server push
    #[test]
    fn replay_pushed_once_and_bounded_spec_sync_5() {
        let mut g = RelayGate::new(RelayLimits { count: 3, bytes: 1 << 20, window_ms: 60_000 });
        let l = LabelId([1; 16]);
        let t = Some(NOW + MAX_DRIFT_MS);
        assert_eq!(g.admit(&l, &id(0), 100, t, NOW), RelayVerdict::Push);
        for _ in 0..1000 {
            assert_eq!(g.admit(&l, &id(0), 100, t, NOW + 1), RelayVerdict::Seen, "a replay floods nobody");
        }
        assert_eq!(g.admit(&l, &id(1), MAX_RELAY_BLOB + 1, t, NOW), RelayVerdict::Refused(Code::TOO_LARGE));
        assert_eq!(g.admit(&l, &id(1), 100, None, NOW), RelayVerdict::Refused(Code::REFUSED));
        assert_eq!(g.admit(&l, &id(1), 100, Some(NOW), NOW), RelayVerdict::Refused(Code::EXPIRED));
        assert_eq!(g.admit(&l, &id(1), 100, Some(NOW + 2 * MAX_DRIFT_MS + 1), NOW), RelayVerdict::Refused(Code::REFUSED), "far future");
        assert_eq!(g.admit(&l, &id(1), 100, t, NOW), RelayVerdict::Push);
        assert_eq!(g.admit(&l, &id(2), 100, t, NOW), RelayVerdict::Push);
        assert_eq!(g.admit(&l, &id(3), 100, t, NOW), RelayVerdict::Refused(Code::RATE_LIMITED), "the label's rate");
        assert_eq!(g.admit(&LabelId([2; 16]), &id(3), 100, t, NOW), RelayVerdict::Push, "per label");
        assert_eq!(g.admit(&l, &id(3), 100, t, NOW + 60_000), RelayVerdict::Push, "next window");
        // past its expiry the pair is forgotten (and the blob refused as expired)
        assert_eq!(g.admit(&l, &id(0), 100, t, NOW + MAX_DRIFT_MS), RelayVerdict::Refused(Code::EXPIRED));
        assert_eq!(g.admit(&l, &id(9), 100, Some(NOW + 3 * MAX_DRIFT_MS), NOW + MAX_DRIFT_MS + 120_000), RelayVerdict::Push);
        assert_eq!(g.remembered(), 1, "expired pairs are forgotten");
    }

    // MAX_RELAY_SEEN: the memory is bounded; past it the earliest-expiring pair goes
    #[test]
    fn remembered_pairs_bounded() {
        let mut g = RelayGate::new(RelayLimits { count: u32::MAX, bytes: u64::MAX, window_ms: 60_000 });
        let l = LabelId([1; 16]);
        for n in 0..(MAX_RELAY_SEEN as u32 + 10) {
            assert_eq!(g.admit(&l, &id(n), 10, Some(NOW + 1_000 + u64::from(n)), NOW), RelayVerdict::Push);
        }
        assert_eq!(g.remembered(), MAX_RELAY_SEEN);
        assert_eq!(g.admit(&l, &id(0), 10, Some(NOW + 1_000), NOW), RelayVerdict::Push, "the earliest went");
        assert_eq!(g.admit(&l, &id(MAX_RELAY_SEEN as u32 + 5), 10, Some(NOW + 1_000 + MAX_RELAY_SEEN as u64 + 5), NOW), RelayVerdict::Seen);
    }
}
