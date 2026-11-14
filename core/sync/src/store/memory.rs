//! The store's memory part (spec/sync-ids.md §5, spec/sync-streams.md §3): ephemeral entries,
//! their tombstones (`MAX_DRIFT`) and bytes, the memory part of the node log (ordered by a
//! counter of its own, no position), the engine's memory holds, and the charges that last only
//! while their connection or this start does. All of it is lost at a restart. Its reads and
//! writes stamp `stamps`, so a memo may read it.

use super::rows::{EntryRow, Source, Usage};
use osis_base::format::TOMBSTONE_LIFETIME_MS;
use osis_base::memo::Stamps;
use osis_base::{BlobId, SyncId, WallMs};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// A row a connection's source keeps: (connection, sync ID, owner tag, key).
pub(crate) type ConnRow = (crate::types::ConnId, SyncId, u8, Vec<u8>);

/// The stamp key of S's listing (any entry of S added or removed).
#[derive(Hash)]
struct Listing<'a>(&'a SyncId);

#[derive(Clone, Default)]
pub(crate) struct Memory {
    pub entries: HashMap<(SyncId, BlobId), EntryRow>,
    /// The memory log: per S, by counter, an entry added (`None`) or removed at a time.
    pub log: BTreeMap<(SyncId, u64), (BlobId, Option<WallMs>)>,
    /// Each entry's latest memory log event.
    pub slot: HashMap<(SyncId, BlobId), u64>,
    pub next: u64,
    pub tombs: HashMap<(SyncId, BlobId), WallMs>,
    /// Tombstones and removal events by when they were made, for the sweep.
    pub aging: BTreeSet<(WallMs, SyncId, BlobId)>,
    pub expiry: BTreeSet<(WallMs, SyncId, BlobId)>,
    pub blobs: HashMap<BlobId, Vec<u8>>,
    /// Blobs the engine holds in memory.
    pub engine: HashSet<BlobId>,
    /// The sync IDs whose ephemeral entries name each blob.
    pub by_blob: HashMap<BlobId, BTreeSet<SyncId>>,
    pub usage: HashMap<SyncId, Usage>,
    /// Bytes charged to each source by ephemeral entries and connections.
    pub charges: HashMap<Source, u64>,
    /// Rows a connection's source keeps for this connection only (stands, deletes seen).
    pub conn_rows: HashMap<ConnRow, Vec<u8>>,
    /// Those rows by when they were written: they end after `TOMBSTONE_LIFETIME` as a record's do.
    pub conn_aging: BTreeSet<(WallMs, ConnRow)>,
    pub stamps: Stamps,
    /// Every entry added, or whose wrap, stamp or deposited flag changed, durable or in memory:
    /// a `Feed<(SyncId, BlobId)>` over it is a reader's cursor of entries to judge (inbox).
    pub fed: Stamps,
    /// Every sync ID shredded (`Store::shred`): a `Feed<SyncId>` over it tells the modules that
    /// keep S in memory per record (opens, streams) to drop it.
    pub shreds: Stamps,
}

impl Memory {
    pub(crate) fn read(&self, s: &SyncId, b: &BlobId) -> Option<&EntryRow> {
        self.stamps.read(&(s, b));
        self.entries.get(&(*s, *b))
    }

    pub(crate) fn list(&self, s: &SyncId) -> Vec<(BlobId, EntryRow)> {
        self.stamps.read(&Listing(s));
        let lo = (*s, 0);
        let hi = (*s, u64::MAX);
        self.log.range(lo..=hi).filter(|(_, (_, gone))| gone.is_none()).filter_map(|(_, (b, _))| self.entries.get(&(*s, *b)).map(|r| (*b, r.clone()))).collect()
    }

    pub(crate) fn usage(&self, s: &SyncId) -> Usage {
        self.stamps.read(&Listing(s));
        self.usage.get(s).copied().unwrap_or_default()
    }

    pub(crate) fn tombstoned(&self, s: &SyncId, b: &BlobId) -> bool {
        self.stamps.read(&(s, b));
        self.tombs.contains_key(&(*s, *b))
    }

    fn moved(&self, s: &SyncId, b: &BlobId) {
        self.stamps.wrote(&(s, b), true);
        self.stamps.wrote(&Listing(s), true);
    }

    fn event(&mut self, s: &SyncId, b: &BlobId, gone: Option<WallMs>) {
        if let Some(old) = self.slot.remove(&(*s, *b)) {
            self.log.remove(&(*s, old));
        }
        self.next += 1;
        self.log.insert((*s, self.next), (*b, gone));
        self.slot.insert((*s, *b), self.next);
    }

    fn count(&mut self, s: &SyncId, r: &EntryRow, sign: bool) {
        let u = self.usage.entry(*s).or_default();
        let op = |x: &mut u64, n: u64| *x = if sign { x.saturating_add(n) } else { x.saturating_sub(n) };
        if !r.role {
            op(&mut u.entries, 1);
            op(&mut u.bytes, r.size + super::ENTRY_OVERHEAD);
        }
        if r.deposited {
            op(&mut u.deposits, 1);
            op(&mut u.deposit_bytes, r.size);
        }
        if let Some(src) = r.charged {
            let c = self.charges.entry(src).or_default();
            op(c, r.size);
        }
    }

    /// Takes an ephemeral entry with its bytes (the caller checked the rules).
    pub(crate) fn insert(&mut self, s: &SyncId, b: &BlobId, mut row: EntryRow, bytes: Vec<u8>) {
        self.tombs.remove(&(*s, *b));
        row.size = bytes.len() as u64;
        self.blobs.entry(*b).or_insert(bytes);
        self.by_blob.entry(*b).or_default().insert(*s);
        if let Some(t) = row.expires {
            self.expiry.insert((t, *s, *b));
        }
        if let Some(old) = self.entries.remove(&(*s, *b)) {
            self.count(s, &old, false);
        }
        self.count(s, &row, true);
        self.entries.insert((*s, *b), row);
        self.event(s, b, None);
        self.moved(s, b);
        self.fed.wrote_added(&(*s, *b), true, true);
    }

    /// Replaces an entry's row (its wrap, stamp, flags, charge).
    pub(crate) fn change(&mut self, s: &SyncId, b: &BlobId, new: EntryRow) {
        let Some(old) = self.entries.remove(&(*s, *b)) else { return };
        self.count(s, &old, false);
        self.count(s, &new, true);
        let seen = (old.wrap, old.stamp, old.deposited) != (new.wrap, new.stamp, new.deposited);
        self.entries.insert((*s, *b), new);
        if seen {
            self.event(s, b, None);
            self.fed.wrote_added(&(*s, *b), true, true);
        }
        self.moved(s, b);
    }

    /// Removes an ephemeral entry (`tomb`: with a tombstone, `MAX_DRIFT`); `expired`: no event.
    pub(crate) fn remove(&mut self, s: &SyncId, b: &BlobId, now: WallMs, tomb: bool, expired: bool) -> bool {
        let held = self.entries.remove(&(*s, *b));
        if let Some(row) = &held {
            self.count(s, row, false);
            if let Some(t) = row.expires {
                self.expiry.remove(&(t, *s, *b));
            }
            if expired {
                if let Some(old) = self.slot.remove(&(*s, *b)) {
                    self.log.remove(&(*s, old));
                }
            } else {
                self.event(s, b, Some(now));
                self.aging.insert((now, *s, *b));
            }
            if let Some(set) = self.by_blob.get_mut(b) {
                set.remove(s);
                if set.is_empty() {
                    self.by_blob.remove(b);
                    if !self.engine.contains(b) {
                        self.blobs.remove(b);
                    }
                }
            }
        }
        if tomb {
            self.tombs.insert((*s, *b), now);
            self.aging.insert((now, *s, *b));
        }
        self.moved(s, b);
        held.is_some()
    }

    /// Drops what S holds here (leaving S).
    pub(crate) fn forget(&mut self, s: &SyncId, now: WallMs) {
        let blobs: Vec<BlobId> = self.entries.keys().filter(|(x, _)| x == s).map(|(_, b)| *b).collect();
        for b in blobs {
            self.remove(s, &b, now, false, true);
        }
        self.tombs.retain(|(x, _), _| x != s);
        self.log.retain(|(x, _), _| x != s);
        self.slot.retain(|(x, _), _| x != s);
        self.usage.remove(s);
        self.conn_forget(|(_, x, _, _)| x != s);
        self.stamps.wrote(&Listing(s), true);
    }

    /// The memory log of S after counter `after`: each entry's latest event, `true` while present.
    pub(crate) fn events(&self, s: &SyncId, after: u64, max: usize) -> (Vec<(u64, BlobId, bool)>, u64) {
        self.stamps.read(&Listing(s));
        let v: Vec<_> = self.log.range((*s, after.saturating_add(1))..=(*s, u64::MAX)).take(max).map(|((_, n), (b, gone))| (*n, *b, gone.is_none())).collect();
        let last = v.last().map_or(after.max(self.next), |e| e.0);
        (v, last)
    }

    /// Sweeps expiry at `now` and tombstones and removal events past `MAX_DRIFT`; whether any.
    pub(crate) fn sweep(&mut self, now: WallMs) -> bool {
        let mut acted = false;
        while let Some(&(t, s, b)) = self.expiry.first() {
            if t.0 > now.0 {
                break;
            }
            self.remove(&s, &b, now, false, true);
            acted = true;
        }
        while let Some(&(t, s, b)) = self.aging.first() {
            if t.0.saturating_add(osis_base::format::MAX_DRIFT_MS) > now.0 {
                break;
            }
            self.aging.pop_first();
            if self.tombs.get(&(s, b)) == Some(&t) {
                self.tombs.remove(&(s, b));
            }
            if let Some(n) = self.slot.get(&(s, b)).copied()
                && self.log.get(&(s, n)).is_some_and(|(_, g)| *g == Some(t))
            {
                self.log.remove(&(s, n));
                self.slot.remove(&(s, b));
            }
            self.moved(&s, &b);
            acted = true;
        }
        while let Some((t, _)) = self.conn_aging.first() {
            if t.0.saturating_add(TOMBSTONE_LIFETIME_MS) > now.0 {
                break;
            }
            let Some((t, row)) = self.conn_aging.pop_first() else { break };
            // a row written again since ages from its new time
            if self.conn_rows.get(&row).is_some_and(|v| v.get(..8) == Some(&t.0.to_be_bytes()[..])) {
                self.conn_rows.remove(&row);
                self.stamps.wrote(&row, true);
                self.stamps.wrote(&("deletes known", row.1), true);
            }
            acted = true;
        }
        acted
    }

    pub(crate) fn next_due(&self) -> Option<WallMs> {
        let e = self.expiry.first().map(|x| x.0);
        let a = self.aging.first().map(|x| WallMs(x.0.0.saturating_add(osis_base::format::MAX_DRIFT_MS)));
        let c = self.conn_aging.first().map(|x| WallMs(x.0.0.saturating_add(TOMBSTONE_LIFETIME_MS)));
        e.into_iter().chain(a).chain(c).min()
    }

    /// Writes (or with `None` removes) a connection's row, written at `at`.
    pub(crate) fn conn_put(&mut self, row: ConnRow, val: Option<(WallMs, Vec<u8>)>) {
        self.stamps.wrote(&row, true);
        match val {
            Some((at, v)) => {
                self.conn_aging.insert((at, row.clone()));
                self.conn_rows.insert(row, v);
            }
            None => drop(self.conn_rows.remove(&row)),
        }
    }

    pub(crate) fn conn_get(&self, row: &ConnRow) -> Option<Vec<u8>> {
        self.stamps.read(row);
        self.conn_rows.get(row).cloned()
    }

    /// Drops connection `c`'s rows (it closed), or every connection's rows of S (S left).
    pub(crate) fn conn_forget(&mut self, keep: impl Fn(&ConnRow) -> bool) {
        self.conn_rows.retain(|r, _| keep(r));
        self.conn_aging.retain(|(_, r)| keep(r));
    }

    /// What a connection's charges held (it closed): the ephemeral entries it brought that still
    /// give nothing held, to drop.
    pub(crate) fn charged_to(&self, src: Source) -> Vec<(SyncId, BlobId)> {
        self.entries.iter().filter(|(_, r)| r.charged == Some(src)).map(|(k, _)| *k).collect()
    }
}
