//! Relay-only entries at a node keeping a sync ID unread (spec/sync-ids.md §6 Relay-only): admitted
//! by prefix expiry and size, counted against a per-sync-ID rate, and taken once per blob within
//! its expiry window (a repeat is dropped: a Stream is never answered).

use crate::msg::Code;
use osis_base::format::{MAX_DRIFT_MS, MAX_RELAY_BLOB};
use crate::SyncId;
use osis_base::BlobId;
use std::collections::{BTreeSet, HashMap, HashSet};

/// What becomes of a relay-only entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayVerdict {
    /// New: push it to the sync ID's other holders.
    Push,
    /// Taken already within its window, or at or below the sync ID's floor: dropped.
    Seen,
    Refused(Code),
}

/// Per-sync-ID relay rate (spec/sync-ids.md §6 rate limits). Resource bound: each relay is pushed to
/// every other holder of the sync ID (0: no ephemeral signals; infinity: a writer or a replayer of stamped
/// blobs sends traffic at line rate times subscribers).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayLimits {
    /// Relays per sync ID and window.
    pub count: u32,
    /// Relayed bytes per sync ID and window.
    pub bytes: u64,
    pub window_ms: u64,
}

impl Default for RelayLimits {
    fn default() -> RelayLimits {
        RelayLimits { count: 6_000, bytes: 32 << 20, window_ms: 60_000 }
    }
}

/// Where a relay-only entry came from: `peer` the connection it came on (`None`: this node's
/// own), `of` how many sources share S here now (its connections and this node). Each source
/// takes at most an equal share of S's rate, so one flooding source (a writer, or a peer passing
/// on a writer's flood) never starves the others' signals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelaySource {
    pub peer: Option<u64>,
    pub of: usize,
}

/// Relayed (sync ID, blob) pairs remembered until their prefix expiry, node-wide. Resource bound:
/// past it the earliest-expiring pair is forgotten and its expiry becomes its sync ID's floor, at
/// or below which that sync ID's relay-only blobs are dropped (spec/sync-ids.md §6 Taken once), so
/// no replay is pushed twice; 0: every relay is dropped once one was; infinity: memory grows with
/// every relay of the last two hours. Each pair costs about 200 bytes (a hash-set and a B-tree entry): 13 MiB at the bound.
pub const MAX_RELAY_SEEN: usize = 1 << 16;

/// The relay state of one node (in memory; a restart forgets it).
#[derive(Clone, Debug)]
pub struct RelayGate {
    pub limits: RelayLimits,
    seen: HashSet<(SyncId, BlobId)>,
    by_expiry: BTreeSet<(u64, SyncId, BlobId)>,
    window: u64,
    used: HashMap<SyncId, (u32, u64)>,
    /// What each source used of its sync ID's rate this window.
    shares: HashMap<(SyncId, Option<u64>), (u32, u64)>,
    /// Per sync ID, the greatest expiry forgotten past `MAX_RELAY_SEEN` (one per sync ID that
    /// overflowed; a past floor drops nothing an unexpired blob could be).
    floor: HashMap<SyncId, u64>,
}

impl Default for RelayGate {
    fn default() -> RelayGate {
        RelayGate::new(RelayLimits::default())
    }
}

impl RelayGate {
    pub fn new(limits: RelayLimits) -> RelayGate {
        RelayGate { limits, seen: HashSet::new(), by_expiry: BTreeSet::new(), window: 0, used: HashMap::new(), shares: HashMap::new(), floor: HashMap::new() }
    }

    /// Admits a stamped relay-only blob of `size` bytes with prefix expiry `expiry` at wall
    /// `now` (spec/sync-ids.md §6): too large, without an expiry, expired or expiring more than
    /// `2 × MAX_DRIFT` ahead (a writer's `ts` at most `MAX_DRIFT` ahead, plus its window) is
    /// refused; a repeat within its window, or one expiring at or below the sync ID's floor, is
    /// `Seen`; past the sync ID's rate, or past `from`'s equal share of it, code 4.
    pub fn admit(&mut self, sync_id: &SyncId, from: RelaySource, blob_id: &BlobId, size: usize, expiry: Option<u64>, now: u64) -> RelayVerdict {
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
        if self.seen.contains(&(*sync_id, *blob_id)) || self.floor.get(sync_id).is_some_and(|f| t <= *f) {
            return RelayVerdict::Seen;
        }
        let w = now / self.limits.window_ms.max(1);
        if w != self.window {
            self.window = w;
            self.used.clear();
            self.shares.clear();
        }
        let size = size as u64;
        let of = from.of.max(1);
        let (count, bytes) = (self.limits.count.div_ceil(of as u32), self.limits.bytes.div_ceil(of as u64));
        let used = self.used.get(sync_id).copied().unwrap_or((0, 0));
        let share = self.shares.get(&(*sync_id, from.peer)).copied().unwrap_or((0, 0));
        if used.0 >= self.limits.count || used.1.saturating_add(size) > self.limits.bytes || share.0 >= count || share.1.saturating_add(size) > bytes {
            return RelayVerdict::Refused(Code::RATE_LIMITED);
        }
        self.used.insert(*sync_id, (used.0 + 1, used.1.saturating_add(size)));
        self.shares.insert((*sync_id, from.peer), (share.0 + 1, share.1.saturating_add(size)));
        self.seen.insert((*sync_id, *blob_id));
        self.by_expiry.insert((t, *sync_id, *blob_id));
        if self.seen.len() > MAX_RELAY_SEEN
            && let Some(first) = self.by_expiry.pop_first()
        {
            self.seen.remove(&(first.1, first.2));
            let f = self.floor.entry(first.1).or_insert(0);
            *f = (*f).max(first.0);
        }
        RelayVerdict::Push
    }

    /// Pairs remembered (tests).
    #[cfg(test)]
    pub fn remembered(&self) -> usize {
        self.seen.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000_000_000;
    /// The node's own sends, its only source of S.
    const ME: RelaySource = RelaySource { peer: None, of: 1 };

    fn id(n: u32) -> BlobId {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&n.to_le_bytes());
        BlobId(b)
    }

    // spec/sync-ids.md §6 (relay-only): a replay within the window is pushed once; expiry,
    // size and rate bound what one replayer can make a node push
    #[test]
    fn replay_pushed_once_and_bounded_spec_sync_ids_6() {
        let mut g = RelayGate::new(RelayLimits { count: 3, bytes: 1 << 20, window_ms: 60_000 });
        let l = SyncId([1; 16]);
        let t = Some(NOW + MAX_DRIFT_MS);
        assert_eq!(g.admit(&l, ME, &id(0), 100, t, NOW), RelayVerdict::Push);
        for _ in 0..1000 {
            assert_eq!(g.admit(&l, ME, &id(0), 100, t, NOW + 1), RelayVerdict::Seen, "a replay floods nobody");
        }
        assert_eq!(g.admit(&l, ME, &id(1), MAX_RELAY_BLOB + 1, t, NOW), RelayVerdict::Refused(Code::TOO_LARGE));
        assert_eq!(g.admit(&l, ME, &id(1), 100, None, NOW), RelayVerdict::Refused(Code::REFUSED));
        assert_eq!(g.admit(&l, ME, &id(1), 100, Some(NOW), NOW), RelayVerdict::Refused(Code::EXPIRED));
        assert_eq!(g.admit(&l, ME, &id(1), 100, Some(NOW + 2 * MAX_DRIFT_MS + 1), NOW), RelayVerdict::Refused(Code::REFUSED), "far future");
        assert_eq!(g.admit(&l, ME, &id(1), 100, t, NOW), RelayVerdict::Push);
        assert_eq!(g.admit(&l, ME, &id(2), 100, t, NOW), RelayVerdict::Push);
        assert_eq!(g.admit(&l, ME, &id(3), 100, t, NOW), RelayVerdict::Refused(Code::RATE_LIMITED), "the sync ID's rate");
        assert_eq!(g.admit(&SyncId([2; 16]), ME, &id(3), 100, t, NOW), RelayVerdict::Push, "per sync ID");
        assert_eq!(g.admit(&l, ME, &id(3), 100, t, NOW + 60_000), RelayVerdict::Push, "next window");
        // past its expiry the pair is forgotten (and the blob refused as expired)
        assert_eq!(g.admit(&l, ME, &id(0), 100, t, NOW + MAX_DRIFT_MS), RelayVerdict::Refused(Code::EXPIRED));
        assert_eq!(g.admit(&l, ME, &id(9), 100, Some(NOW + 3 * MAX_DRIFT_MS), NOW + MAX_DRIFT_MS + 120_000), RelayVerdict::Push);
        assert_eq!(g.remembered(), 1, "expired pairs are forgotten");
    }

    // spec/sync-ids.md §6 (taken once): the memory is bounded; past it the earliest-expiring pair
    // goes and its expiry becomes the sync ID's floor, at or below which its blobs are dropped
    #[test]
    fn remembered_pairs_bounded_by_a_floor_spec_sync_ids_6() {
        let mut g = RelayGate::new(RelayLimits { count: u32::MAX, bytes: u64::MAX, window_ms: 60_000 });
        let l = SyncId([1; 16]);
        for n in 0..(MAX_RELAY_SEEN as u32 + 10) {
            assert_eq!(g.admit(&l, ME, &id(n), 10, Some(NOW + 1_000 + u64::from(n)), NOW), RelayVerdict::Push);
        }
        assert_eq!(g.remembered(), MAX_RELAY_SEEN);
        assert_eq!(g.admit(&l, ME, &id(0), 10, Some(NOW + 1_000), NOW), RelayVerdict::Seen, "the earliest went: replayed, it is at the floor");
        assert_eq!(g.admit(&l, ME, &id(u32::MAX), 10, Some(NOW + 1_009), NOW), RelayVerdict::Seen, "a new blob at or below the floor");
        assert_eq!(g.admit(&SyncId([2; 16]), ME, &id(0), 10, Some(NOW + 1_000), NOW), RelayVerdict::Push, "the floor is per sync ID");
        assert_eq!(g.admit(&l, ME, &id(MAX_RELAY_SEEN as u32 + 5), 10, Some(NOW + 1_000 + MAX_RELAY_SEEN as u64 + 5), NOW), RelayVerdict::Seen);
        assert_eq!(g.admit(&l, ME, &id(u32::MAX - 1), 10, Some(NOW + 1_010 + MAX_RELAY_SEEN as u64), NOW), RelayVerdict::Push, "above the floor");
    }

    // spec/sync-ids.md §6 (Relay-only): each source takes at most an equal share of S's rate, so
    // one flooding source leaves the others theirs
    #[test]
    fn a_flooding_source_leaves_the_others_their_share_spec_sync_ids_6() {
        let mut g = RelayGate::new(RelayLimits { count: 10, bytes: 1 << 20, window_ms: 60_000 });
        let l = SyncId([1; 16]);
        let t = Some(NOW + MAX_DRIFT_MS);
        let (flood, honest) = (RelaySource { peer: Some(1), of: 2 }, RelaySource { peer: Some(2), of: 2 });
        let pushed = (0..100u32).filter(|n| g.admit(&l, flood, &id(*n), 100, t, NOW) == RelayVerdict::Push).count();
        assert_eq!(pushed, 5, "the flooder's half of S's rate");
        for n in 0..5u32 {
            assert_eq!(g.admit(&l, honest, &id(1_000 + n), 100, t, NOW), RelayVerdict::Push, "the other source's share stays");
        }
        assert_eq!(g.admit(&l, honest, &id(2_000), 100, t, NOW), RelayVerdict::Refused(Code::RATE_LIMITED), "its share, and S's rate, used up");
    }
}
