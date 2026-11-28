//! The product's ground: the engine's facade, the store, opens, streams, read and unread.

use super::{Ground, Net};
use crate::opens::Opens;
use crate::read::{Read, Verdict};
use crate::store::Source;
use crate::streams::Streams;
use crate::types::{ConnId, Cx, Position, RecordId, Result};
use crate::unread::Unread;
use osis_base::{BlobId, CommitId, SyncId, Tid, Time};
use osis_store::Shred;
use osis_engine::sync::SyncSet;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// What status reads when asked: streams' caught up, full and refusals, unread's stranded.
#[derive(Clone, Copy)]
pub struct NetView<'a> {
    pub streams: &'a Streams,
    pub unread: &'a Unread,
}

impl Net for NetView<'_> {
    fn caught_since(&self, conn: ConnId, s: &SyncId) -> Option<u64> {
        self.streams.caught_since(conn, s)
    }
    fn pull_seq(&self) -> u64 {
        self.streams.pull_seq()
    }
    fn full(&self, conn: ConnId, s: &SyncId) -> bool {
        self.streams.known().full(conn, s)
    }
    fn refusing(&self, at: Source, s: &SyncId) -> bool {
        self.streams.known().refusing(at, s)
    }
    fn stranded(&self, s: &SyncId) -> bool {
        self.unread.stranded(s)
    }
}

/// The sync store's rows `Z/p/ s`: the wall time a pass of S under way began (8 bytes).
const BEGUN: &[u8] = b"Z/p/";

pub struct Live<'a, 'b> {
    pub cx: &'a mut Cx<'b>,
    pub opens: &'a Opens,
    pub streams: &'a Streams,
    pub read: &'a Read,
    pub unread: &'a Unread,
    pub leave: &'a crate::leave::Leave,
}

impl Live<'_, '_> {
    fn net(&self) -> NetView<'_> {
        NetView { streams: self.streams, unread: self.unread }
    }
}

impl Net for Live<'_, '_> {
    fn caught_since(&self, conn: ConnId, s: &SyncId) -> Option<u64> {
        self.net().caught_since(conn, s)
    }
    fn pull_seq(&self) -> u64 {
        self.net().pull_seq()
    }
    fn full(&self, conn: ConnId, s: &SyncId) -> bool {
        self.net().full(conn, s)
    }
    fn refusing(&self, at: Source, s: &SyncId) -> bool {
        self.net().refusing(at, s)
    }
    fn stranded(&self, s: &SyncId) -> bool {
        self.net().stranded(s)
    }
}

impl Ground for Live<'_, '_> {
    fn mono(&self) -> osis_base::Mono {
        self.cx.mono
    }
    fn now(&self) -> Time {
        self.cx.now
    }
    fn passes_begun(&mut self) -> Result<BTreeMap<SyncId, Time>> {
        let rows = self.cx.store.with_read(|t| t.scan_local(BEGUN, b"", usize::MAX))?;
        let mut out = BTreeMap::new();
        for (k, v) in rows {
            let s = k.get(BEGUN.len()..).and_then(|x| x.try_into().ok()).map(SyncId);
            let at = v.as_slice().try_into().ok().map(u64::from_be_bytes).map(Time);
            let (Some(s), Some(at)) = (s, at) else { return Err(crate::types::Error::Store(osis_store::Error::Corrupt("status pass start row"))) };
            out.insert(s, at);
        }
        Ok(out)
    }
    fn set_pass_begun(&mut self, s: &SyncId, at: Option<Time>) -> Result<()> {
        let key = [BEGUN, &s.0].concat();
        self.cx.store.with_tx(|t| match at {
            Some(at) => t.put_local(&key, &at.0.to_be_bytes(), Shred::No),
            None => t.remove_local(&key, Shred::No).map(drop),
        })
    }
    fn syncs(&mut self) -> Arc<SyncSet> {
        Arc::new(SyncSet { ids: self.cx.store.syncs(), ..SyncSet::default() })
    }
    fn stamped(&mut self, s: &SyncId) -> Result<Vec<BlobId>> {
        Ok(self.cx.store.entries(s)?.into_iter().filter(|e| e.stamp.is_some()).map(|e| e.blob).collect())
    }
    fn knows(&self, at: Source, conn: ConnId, s: &SyncId, b: &BlobId) -> bool {
        self.streams.knows(at, Some(conn), s, b)
    }
    fn knows_now(&self, at: Source, s: &SyncId, b: &BlobId) -> bool {
        self.streams.knows(at, self.opens.conn_of(at), s, b)
    }
    fn reported(&self, conn: ConnId, s: &SyncId) -> Option<Position> {
        self.opens.reported_at(conn, s).map(|(p, _)| *p)
    }
    fn until(&self, conn: ConnId, s: &SyncId) -> Option<Position> {
        self.opens.member(conn, s).and_then(|m| m.until)
    }
    fn records_holding(&mut self, s: &SyncId) -> Result<BTreeSet<RecordId>> {
        self.opens.records_holding(self.cx.store, s)
    }
    fn own_commits(&mut self, s: &SyncId) -> Result<Arc<BTreeSet<CommitId>>> {
        Ok(self.cx.engine.own_commits(s)?)
    }
    fn own_feed(&mut self) -> osis_engine::sync::OwnFeed {
        self.cx.engine.own_feed()
    }
    fn follow_own(&mut self) -> Result<()> {
        Ok(self.cx.engine.follow_own()?)
    }
    fn own_has(&mut self, s: &SyncId, c: &CommitId) -> bool {
        self.cx.engine.own_has(s, c)
    }
    fn self_removals(&mut self) -> Arc<BTreeSet<CommitId>> {
        self.cx.engine.waiting_removals()
    }
    fn verdict(&self, s: &SyncId, c: &CommitId) -> Option<Verdict> {
        self.read.verdict(s, c)
    }
    fn commit_entries(&mut self, s: &SyncId, c: &CommitId) -> Result<Vec<BlobId>> {
        let mut out = Vec::new();
        for b in self.cx.engine.commit_blobs(c)?.iter() {
            if self.cx.store.entry(s, b)?.is_some() {
                out.push(*b);
            }
        }
        Ok(out)
    }
    fn first_logged(&mut self, s: &SyncId, b: &BlobId) -> Result<Option<Position>> {
        self.cx.store.first_logged(s, b)
    }
    fn elsewhere(&mut self, s: &SyncId, b: &BlobId) -> Result<bool> {
        self.cx.store.elsewhere(s, b)
    }
    fn set_elsewhere(&mut self, s: &SyncId, b: &BlobId) -> Result<()> {
        self.cx.store.set_elsewhere(s, b)
    }
    fn waited(&mut self, s: &SyncId, own: bool) -> Result<bool> {
        self.opens.waited(self.cx.engine, self.cx.store, s, own)
    }
    fn counts_for(&mut self, c: &CommitId, node: Option<Tid>) -> bool {
        self.cx.engine.counts_for_leave(c, node.as_ref())
    }
    fn removal_done(&mut self, c: &CommitId) -> Result<()> {
        Ok(self.cx.engine.removal_done(c)?)
    }
    fn pass_wanted(&mut self, s: &SyncId) -> Result<Option<u64>> {
        Ok(self.cx.engine.pass_wanted(s)?)
    }
    fn module_passes(&mut self) -> Arc<BTreeMap<SyncId, u64>> {
        Arc::new(self.read.passes_wanted())
    }
    fn leave_passes(&mut self) -> Arc<BTreeMap<SyncId, u64>> {
        Arc::new(self.leave.passes_wanted())
    }
    fn stranding(&mut self, s: &SyncId) -> Result<Option<Arc<osis_engine::sync::Stranding>>> {
        Ok(self.cx.engine.stranded(s)?.map(Arc::new))
    }
    fn begin_pass(&mut self) -> u64 {
        self.cx.engine.begin_pass()
    }
    fn note_complete_pass(&mut self, s: &SyncId, began: u64) -> Result<()> {
        self.cx.engine.note_complete_pass(s, began)?;
        // what a complete pass's end decides (spec/permissions.md §3 Complete pass, §5.5): the
        // engine re-seals, adds history and makes S's actor's owed rotations once every sync ID
        // of that actor had one
        for actor in self.cx.engine.sync_owners(s)? {
            self.cx.engine.pass_end(&actor)?;
        }
        // what the pass brought that nothing held needs goes (spec/commits.md §5 What a held
        // thing needs)
        self.cx.engine.settle_needs()?;
        Ok(())
    }
    fn settle_lost(&mut self) -> Result<()> {
        Ok(self.cx.engine.settle_lost()?)
    }
}
