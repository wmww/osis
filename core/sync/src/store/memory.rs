//! The store's memory part beside its rows (spec/sync-ids.md §5, spec/sync-streams.md §3): the
//! memory part of the node log (ordered by a counter of its own, no position), what a held
//! ephemeral blob costs, the charges ephemeral entries make, the rows a connection keeps while it
//! lasts, and the store's feeds. Ephemeral entries themselves, their tombstones, bytes and index
//! rows are the memory store's rows (`Inner::ram`). All of it is lost at a restart. Its reads and
//! writes stamp `stamps`, so a memo may read it.

use super::rows::Source;
use osis_base::format::{MAX_DRIFT_MS, TOMBSTONE_LIFETIME_MS};
use osis_base::memo::Stamps;
use osis_base::{BlobId, SyncId, WallMs};
use std::collections::{BTreeMap, BTreeSet};

/// A row a connection's source keeps: (connection, sync ID, owner tag, key).
pub(crate) type ConnRow = (crate::types::ConnId, SyncId, u8, Vec<u8>);

/// The stamp key of S's memory log.
#[derive(Hash)]
struct Listing<'a>(&'a SyncId);

#[derive(Clone, Default)]
pub(crate) struct Memory {
    /// The memory log: per S, by counter, an entry added (`None`) or removed at a time.
    log: BTreeMap<(SyncId, u64), (BlobId, Option<WallMs>)>,
    /// Each entry's latest memory log event.
    slot: BTreeMap<(SyncId, BlobId), u64>,
    /// The memory log by counter alone: which sync IDs moved past a mark (`since`).
    by_n: BTreeMap<u64, SyncId>,
    pub next: u64,
    /// Removal events by when they were made, for the sweep.
    aging: BTreeSet<(WallMs, SyncId, BlobId)>,
    /// What a blob of a held ephemeral commit from another node costs held here, past its bytes
    /// (`Engine::memory_charge`; spec/sync-compaction.md §2 Caps): every entry naming it, under
    /// any sync ID, counts the larger. Kept while an entry names the blob.
    pub estimate: BTreeMap<BlobId, u64>,
    /// Bytes charged to each source by ephemeral entries.
    pub charges: BTreeMap<Source, u64>,
    /// Rows a connection's source keeps for this connection only (stands, deletes seen).
    pub conn_rows: BTreeMap<ConnRow, Vec<u8>>,
    /// Those rows by when they were written: they end after `TOMBSTONE_LIFETIME` as a record's do.
    conn_aging: BTreeSet<(WallMs, ConnRow)>,
    pub stamps: Stamps,
    /// Every entry added, removed, or whose wrap, stamp or deposited flag changed, durable or in
    /// memory: a `Feed<(SyncId, BlobId)>` over it is a reader's cursor of entries to judge
    /// (inbox, the store's parked entries).
    pub fed: Stamps,
    /// Every sync ID shredded (`Store::shred`): a `Feed<SyncId>` over it tells the modules that
    /// keep S in memory per record (opens, streams) to drop it.
    pub shreds: Stamps,
    /// Every sync ID kept unread whose head came back within its keys (`Store::set_unheld`
    /// false after true): a `Feed<SyncId>` over it tells streams to fetch S anew.
    pub anew: Stamps,
    /// The sync IDs this node syncs (`Store::set_holdings`), each moved one fed: a
    /// `Feed<SyncId>` over it is a module's cursor of what to follow anew (`set::SyncsFollow`).
    pub syncs: Stamps,
    /// Every blob no entry names any more, durable or in memory: a `Feed<BlobId>` over it tells
    /// the store's follow that a commit's last carrier may have gone (spec/commits.md §4 Pending
    /// storage).
    pub unnamed: Stamps,
}

impl Memory {
    /// Logs entry `b` of S added (`gone` none) or removed at `gone`, over its earlier event.
    pub(crate) fn event(&mut self, s: &SyncId, b: &BlobId, gone: Option<WallMs>) {
        self.unlog(s, b);
        self.next += 1;
        self.log.insert((*s, self.next), (*b, gone));
        self.by_n.insert(self.next, *s);
        self.slot.insert((*s, *b), self.next);
        if let Some(at) = gone {
            self.aging.insert((at, *s, *b));
        }
    }

    /// Drops entry `b` of S's event (an expiry serves none).
    pub(crate) fn unlog(&mut self, s: &SyncId, b: &BlobId) {
        if let Some(old) = self.slot.remove(&(*s, *b)) {
            self.log.remove(&(*s, old));
            self.by_n.remove(&old);
        }
        self.stamps.wrote(&Listing(s), true);
    }

    /// The blobs of S's entries present, oldest event first.
    pub(crate) fn present(&self, s: &SyncId) -> impl Iterator<Item = BlobId> + '_ {
        self.log.range((*s, 0)..=(*s, u64::MAX)).filter(|(_, (_, gone))| gone.is_none()).map(|(_, (b, _))| *b)
    }

    /// Drops S's log and connection rows (leaving S).
    pub(crate) fn forget(&mut self, s: &SyncId) {
        self.log.retain(|(x, _), _| x != s);
        self.by_n.retain(|_, x| x != s);
        self.slot.retain(|(x, _), _| x != s);
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

    /// The memory log's events after counter `after`, each with its sync ID: O(those).
    pub(crate) fn since(&self, after: u64) -> Vec<(u64, SyncId)> {
        self.by_n.range(after.saturating_add(1)..).map(|(n, s)| (*n, *s)).collect()
    }

    /// Sweeps removal events past `MAX_DRIFT` and connection rows past `TOMBSTONE_LIFETIME`;
    /// whether any.
    pub(crate) fn sweep(&mut self, now: WallMs) -> bool {
        let mut acted = false;
        while let Some(&(t, s, b)) = self.aging.first() {
            if t.0.saturating_add(MAX_DRIFT_MS) > now.0 {
                break;
            }
            self.aging.pop_first();
            if let Some(n) = self.slot.get(&(s, b)).copied()
                && self.log.get(&(s, n)).is_some_and(|(_, g)| *g == Some(t))
            {
                self.unlog(&s, &b);
            }
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
        let a = self.aging.first().map(|x| WallMs(x.0.0.saturating_add(MAX_DRIFT_MS)));
        let c = self.conn_aging.first().map(|x| WallMs(x.0.0.saturating_add(TOMBSTONE_LIFETIME_MS)));
        a.into_iter().chain(c).min()
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
}
