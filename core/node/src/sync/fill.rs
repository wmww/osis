//! A label's first sync at a host (spec/sync.md §6): list its entries, then fetch them in the
//! order their wraps give: what judging needs first, then newest first. Nothing about a body
//! changes: one not fetched yet is one not received. Only the order, and when the pass ends.

use super::state::Kind;
use super::{ConnId, HostKey, LConn, Phase, SyncEngine};
use crate::error::Result;
use osis_base::{BlobId, LabelId};
use osis_proto::Cursor;
use osis_proto::client::STALL_TIMEOUT_MS;
use std::collections::BTreeSet;

/// Queue rank of what judging needs (order 0).
const FIRST: u64 = 0;
/// Queue rank of what does not open and the host holds deposited: inbox blobs (a grant or invite
/// to the node's actors) and a reader's deposits under an epoch not held. As many as the host's
/// deposit budget holds, whatever the label holds besides.
const DEPOSITED: u64 = 1;
/// Queue rank of the rest of what does not open: chunks, epochs not held.
const LAST: u64 = u64::MAX;

/// One label's fill on one connection.
#[derive(Default)]
pub(crate) struct Fill {
    /// Entries to fetch, by rank.
    queue: BTreeSet<(u64, BlobId)>,
    /// The batch asked for.
    asked: Vec<BlobId>,
    /// The listing ran to its end.
    listed: bool,
    /// Rank `FIRST` is fetched: a pass may run.
    pub first_done: bool,
    /// The host's position: the node's cursor moves when the fill ends (and to the listing's end).
    cursor: Option<Cursor>,
    /// Secrets held when the ranks were taken.
    secrets: usize,
}

impl Fill {
    pub fn listed(&self) -> bool {
        self.listed
    }
}

impl SyncEngine {
    /// The rank of entry `b`. Everything listed is fetched, as a replay brought it inline; what
    /// no writer vouched for and does not open then goes (`drop_unvouched`).
    fn rank(&self, secrets: &[osis_crypto::Secret32], host: HostKey, l: &LabelId, b: &BlobId, wrap: &[u8]) -> u64 {
        match osis_label::wrap_order(secrets.iter(), b, wrap) {
            // newest first; never `LAST`, and a wrap's own word can do no more than `FIRST`
            Some(t) => if t == FIRST { FIRST } else { (LAST - 1).saturating_sub(t) },
            None if self.state.deposited.contains(&(host, *l, *b)) => DEPOSITED,
            None => LAST,
        }
    }

    fn fill_secrets(&mut self, conn: ConnId, l: &LabelId) -> Vec<osis_crypto::Secret32> {
        self.group_of(l, Some(conn)).map(|g| self.read_secrets(&g)).unwrap_or_default()
    }

    /// Starts `l`'s fill on `conn`, once it is known at this host: the entries it has listed
    /// and not fetched are queued (a connection lost or a restart mid-fill lists no more than
    /// what came since). Marked in the store until it ends.
    pub(crate) fn fill_start(&mut self, conn: ConnId, l: LabelId) {
        let Some(host) = self.conns.get(&conn).map(|c| c.host) else { return };
        self.state.set_filling(host, l, true);
        let secrets = self.fill_secrets(conn, &l);
        let mut queue = BTreeSet::new();
        if self.state.cursors.contains_key(&(host, l)) {
            for b in self.state.of_kind(&l, Kind::TAG_UNKNOWN) {
                let Some(e) = self.state.entries.get(&(l, b)) else { continue };
                let r = self.rank(&secrets, host, &l, &b, &e.wrap);
                if self.state.is_present(&host, &l, &b) && !self.engine.has_blob(&b) {
                    queue.insert((r, b));
                }
            }
        }
        let n = self.secrets_count();
        if let Some(lc) = self.lc_mut(conn, &l) {
            lc.fill = Some(Fill { queue, secrets: n, ..Fill::default() });
        }
    }

    /// Queues entries a Sync or push announced without bytes.
    pub(crate) fn fill_add(&mut self, conn: ConnId, l: LabelId, ids: &[BlobId]) {
        if ids.is_empty() {
            return;
        }
        let Some(host) = self.conns.get(&conn).map(|c| c.host) else { return };
        let secrets = self.fill_secrets(conn, &l);
        let ranked: Vec<(u64, BlobId)> = ids.iter().filter_map(|b| self.state.entries.get(&(l, *b)).map(|e| (self.rank(&secrets, host, &l, b, &e.wrap), *b))).collect();
        if let Some(f) = self.lc_mut(conn, &l).and_then(|x| x.fill.as_mut()) {
            f.queue.extend(ranked);
        }
    }

    /// The fill holds the position: `true` when `l` fills on `conn`.
    pub(crate) fn fill_cursor(&mut self, conn: ConnId, l: &LabelId, c: Cursor) -> bool {
        match self.lc_mut(conn, l).and_then(|x| x.fill.as_mut()) {
            Some(f) => {
                f.cursor = Some(c);
                true
            }
            None => false,
        }
    }

    /// The listing ended: whether `l` fills on `conn`. Its end is the position to go on from.
    pub(crate) fn fill_listed(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<super::Action>) -> Result<bool> {
        let Some(host) = self.conns.get(&conn).map(|c| c.host) else { return Ok(false) };
        let Some(f) = self.lc_mut(conn, &l).and_then(|x| x.fill.as_mut()) else { return Ok(false) };
        f.listed = true;
        if let Some(c) = f.cursor {
            self.state.set_cursor(host, l, Some(c));
        }
        if let Some(lc) = self.lc_mut(conn, &l) {
            lc.syncing = false;
            lc.synced = true;
        }
        self.fill_more(conn, l, out)?;
        Ok(true)
    }

    /// Asks for the next batch once the last is answered; ends the fill when nothing is left.
    pub(crate) fn fill_more(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<super::Action>) -> Result<()> {
        let (secrets_now, now) = (self.secrets_count(), self.raw_now());
        let Some(c) = self.conns.get_mut(&conn) else { return Ok(()) };
        let host = c.host;
        let Some(lc) = c.labels.get_mut(&l) else { return Ok(()) };
        if lc.phase != Phase::Open || !lc.fill.as_ref().is_some_and(|f| f.listed) {
            return Ok(());
        }
        let Some(mut f) = lc.fill.take() else { return Ok(()) };
        // the batch is waited on while it counts as asked (`asked`): past the stall time its host
        // may be trickling the reply, and the fill goes on (what it lacks is asked elsewhere)
        if f.asked.iter().filter_map(|b| c.req.fetching.get(b)).any(|at| at.saturating_add(STALL_TIMEOUT_MS) > now) {
            if let Some(lc) = self.lc_mut(conn, &l) {
                lc.fill = Some(f);
            }
            return Ok(());
        }
        // secrets came: what did not open may be anywhere in the order
        if f.secrets != secrets_now {
            f.secrets = secrets_now;
            let secrets = self.fill_secrets(conn, &l);
            for (_, b) in f.queue.split_off(&(LAST, BlobId([0; 32]))) {
                let r = self.state.entries.get(&(l, b)).map(|e| self.rank(&secrets, host, &l, &b, &e.wrap));
                f.queue.extend(r.map(|r| (r, b)));
            }
        }
        let first_now = !f.first_done && f.queue.first().is_none_or(|x| x.0 != FIRST);
        f.first_done |= first_now;
        let missing = |s: &Self, b: &BlobId| s.conns.get(&conn).is_some_and(|c| c.req.missing.contains(b));
        let mut ids = Vec::new();
        // what judging needs goes alone: it may give the secrets that order the rest
        let mut first = None;
        while let Some(&(r, b)) = f.queue.first() {
            if ids.len() >= self.cfg.fill_batch.max(1) || (!ids.is_empty() && first != Some(r == FIRST)) {
                break;
            }
            f.queue.pop_first();
            if self.state.entries.contains_key(&(l, b)) && self.state.is_present(&host, &l, &b) && !missing(self, &b) && !self.engine.has_blob(&b) && self.may_ask(conn, l, &b) {
                first = Some(r == FIRST);
                ids.push(b);
            }
        }
        if ids.is_empty() {
            let cursor = f.cursor;
            if let Some(lc) = self.lc_mut(conn, &l) {
                lc.fill = None;
                lc.dirty = true;
            }
            self.state.set_filling(host, l, false);
            if let Some(x) = cursor {
                self.state.set_cursor(host, l, Some(x));
            }
            // with bytes inline from here on, and what came since; its end is the pass's
            return self.sync_label(conn, l, out);
        }
        f.asked = ids.clone();
        if let Some(lc) = self.lc_mut(conn, &l) {
            lc.fill = Some(f);
            lc.dirty |= first_now;
        }
        // looked at again when the batch goes stale (`timers`), if no answer came first
        self.settle_by(now.saturating_add(STALL_TIMEOUT_MS), l);
        self.fetch_on(conn, l, ids, out)
    }

    /// Whether a fill has not all that judging needs: the group memberships among it. A label not
    /// open at a host waits for nobody (a host refusing it may do so for good).
    pub fn fill_before_passes(&self) -> bool {
        self.conns.values().any(|c| c.labels.values().any(LConn::first_waits))
    }

    /// `fill_before_passes`, of `l`.
    pub(crate) fn fill_first_waits(&self, l: &LabelId) -> bool {
        self.conns.values().any(|c| c.labels.get(l).is_some_and(LConn::first_waits))
    }

    /// Whether `l` is filling at a host it is open at: entries that open may be unfetched.
    pub(crate) fn filling(&self, l: &LabelId) -> bool {
        self.conns.values().any(|c| c.labels.get(l).is_some_and(|x| x.phase == Phase::Open && x.fill.is_some()))
    }
}
