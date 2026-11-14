//! A label's listing at a peer that cannot read it (spec/sync-judgement.md §2): its stream lists the entries (announced without
//! bytes), then they are fetched in the order their wraps give: what judging needs first, then
//! newest first. Nothing about a body changes: one not fetched yet is one not received. Only the
//! order, and when the pass ends.

use super::state::Kind;
use super::{ConnId, PeerKey, LabelAt, SyncEngine};
use crate::error::Result;
use osis_base::{BlobId, LabelId};
use osis_proto::window::STALL_TIMEOUT_MS;
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
#[derive(Clone, Default)]
pub(crate) struct Fill {
    /// Entries to fetch, by rank.
    queue: BTreeSet<(u64, BlobId)>,
    /// The batch asked for.
    asked: Vec<BlobId>,
    /// Entries passed over while asked elsewhere (`may_ask`), with their ranks: queued again once
    /// that fetch counts as asked no longer, so a source trickling it holds it for the stall time
    /// only, not until this fill's end.
    skipped: Vec<(u64, BlobId)>,
    /// The listing ran to its end.
    listed: bool,
    /// Rank `FIRST` is fetched, or a batch went unanswered past the stall time: a pass may run.
    pub first_done: bool,
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
    fn rank(&self, secrets: &[osis_crypto::Secret32], host: PeerKey, l: &LabelId, b: &BlobId, wrap: &[u8]) -> u64 {
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

    /// Starts `l`'s fill on `conn`: the entries known there and not fetched are queued (a stream
    /// resumed mid-fill lists no more than what came since). Marked in the store until it ends.
    pub(crate) fn fill_start(&mut self, conn: ConnId, l: LabelId) {
        let Some(host) = self.conns.get(&conn).and_then(|c| c.peer) else { return };
        self.state.set_filling(host, l, true);
        let secrets = self.fill_secrets(conn, &l);
        let mut queue = BTreeSet::new();
        for b in self.state.of_kind(&l, Kind::TAG_UNKNOWN) {
            let Some(e) = self.state.entries.get(&(l, b)) else { continue };
            let r = self.rank(&secrets, host, &l, &b, &e.wrap);
            if self.state.is_present(&host, &l, &b) && !self.opens_here(&l, &b) {
                queue.insert((r, b));
            }
        }
        let n = self.secrets_count();
        if let Some(lc) = self.label_at_mut(conn, &l) {
            lc.fill = Some(Fill { queue, secrets: n, ..Fill::default() });
        }
    }

    /// Queues entries the stream announced without bytes.
    pub(crate) fn fill_add(&mut self, conn: ConnId, l: LabelId, ids: &[BlobId]) {
        if ids.is_empty() {
            return;
        }
        let Some(host) = self.conns.get(&conn).and_then(|c| c.peer) else { return };
        let secrets = self.fill_secrets(conn, &l);
        let ranked: Vec<(u64, BlobId)> = ids.iter().filter_map(|b| self.state.entries.get(&(l, *b)).map(|e| (self.rank(&secrets, host, &l, b, &e.wrap), *b))).collect();
        if let Some(f) = self.label_at_mut(conn, &l).and_then(|x| x.fill.as_mut()) {
            f.queue.extend(ranked);
        }
    }

    /// The listing ended (the stream read `l` to the peer's end): the fill fetches on. Whether
    /// `l` fills on `conn`.
    pub(crate) fn fill_listed(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<super::Action>) -> Result<bool> {
        let Some(f) = self.label_at_mut(conn, &l).and_then(|x| x.fill.as_mut()) else { return Ok(false) };
        f.listed = true;
        // listed: the label's work set judges everything at its next pass (`stream_read`)
        if let Some(lc) = self.label_at_mut(conn, &l)
            && !std::mem::replace(&mut lc.synced, true)
        {
            self.work_mut(l).touched.full = true;
        }
        self.fill_more(conn, l, out)?;
        Ok(true)
    }

    /// Asks for the next batch once the last is answered; ends the fill when nothing is left.
    pub(crate) fn fill_more(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<super::Action>) -> Result<()> {
        let (secrets_now, now) = (self.secrets_count(), self.now());
        let Some(c) = self.conns.get_mut(&conn) else { return Ok(()) };
        let Some(host) = c.peer else { return Ok(()) };
        let Some(lc) = c.labels.get_mut(&l) else { return Ok(()) };
        if !lc.phase.is_open() || !lc.fill.as_ref().is_some_and(|f| f.listed) {
            return Ok(());
        }
        let Some(mut f) = lc.fill.take() else { return Ok(()) };
        // the batch is waited on: the host answers in order, so a next one would wait behind it.
        // Passes wait on it only while it counts as asked (`asked`): past the stall time the host
        // may be trickling the reply, and what the label lacks is asked elsewhere
        let out_at: Vec<u64> = f.asked.iter().filter_map(|b| SyncEngine::stream_asked_at(&self.streams, conn, b)).collect();
        if !out_at.is_empty() {
            if !f.first_done && out_at.iter().all(|at| at.saturating_add(STALL_TIMEOUT_MS) <= now) {
                f.first_done = true;
                self.fill_due.insert(l);
            }
            lc.fill = Some(f);
            return Ok(());
        }
        // what was passed over for a fetch elsewhere that failed or went stale is this host's to ask
        let (back, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut f.skipped).into_iter().partition(|(_, b)| self.asked(b).is_none());
        f.skipped = keep;
        f.queue.extend(back);
        // secrets came: what did not open may be anywhere in the order
        if f.secrets != secrets_now {
            f.secrets = secrets_now;
            let secrets = self.fill_secrets(conn, &l);
            for (_, b) in f.queue.split_off(&(LAST, BlobId([0; 32]))) {
                let r = self.state.entries.get(&(l, b)).map(|e| self.rank(&secrets, host, &l, &b, &e.wrap));
                f.queue.extend(r.map(|r| (r, b)));
            }
            for x in f.skipped.iter_mut().filter(|x| x.0 == LAST) {
                x.0 = self.state.entries.get(&(l, x.1)).map_or(LAST, |e| self.rank(&secrets, host, &l, &x.1, &e.wrap));
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
            if self.state.entries.contains_key(&(l, b)) && self.state.is_present(&host, &l, &b) && !missing(self, &b) && !self.opens_here(&l, &b) {
                if self.may_ask(conn, l, &b) {
                    first = Some(r == FIRST);
                    ids.push(b);
                } else {
                    f.skipped.push((r, b));
                }
            }
        }
        if ids.is_empty() {
            if let Some(lc) = self.label_at_mut(conn, &l) {
                lc.fill = None;
            }
            self.fill_due.insert(l);
            self.state.set_filling(host, l, false);
            // its end is the pass's; the stream's bodies come inline from here on
            self.stream_read(conn, l, out)?;
            return self.stream_ask(conn, false, out);
        }
        f.asked = ids.clone();
        if let Some(lc) = self.label_at_mut(conn, &l) {
            lc.fill = Some(f);
        }
        if first_now {
            self.fill_due.insert(l);
        }
        // looked at again when the batch goes stale (`timers`), if no answer came first
        self.settle_by(now.saturating_add(STALL_TIMEOUT_MS), l);
        self.fetch_on(conn, l, ids, out)
    }

    /// The connections where `l`'s fill has its listing (tests).
    #[doc(hidden)]
    pub fn fills_listed(&self, l: &LabelId) -> usize {
        self.conns.values().filter(|c| c.labels.get(l).is_some_and(|x| x.fill.as_ref().is_some_and(|f| f.listed))).count()
    }

    /// Whether a fill has not all that judging needs: the group memberships among it. A label not
    /// open at a host waits for nobody (a host refusing it may do so for good).
    pub fn fill_before_passes(&self) -> bool {
        self.conns.values().any(|c| c.labels.values().any(LabelAt::first_waits))
    }

    /// `fill_before_passes`, of `l`.
    pub(crate) fn fill_first_waits(&self, l: &LabelId) -> bool {
        self.conns.values().any(|c| c.labels.get(l).is_some_and(LabelAt::first_waits))
    }

    /// Whether `l` is filling at a host it is open at: entries that open may be unfetched.
    pub(crate) fn filling(&self, l: &LabelId) -> bool {
        self.conns.values().any(|c| c.labels.get(l).is_some_and(|x| x.phase.is_open() && x.fill.is_some()))
    }
}
