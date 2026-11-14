//! The product's ground: the engine's facade, the store, opens, streams, read and unread.

use super::{Ground, Net};
use crate::opens::Opens;
use crate::read::{Read, Verdict};
use crate::store::Source;
use crate::streams::Streams;
use crate::types::{ConnId, Cx, Position, RecordId, Result};
use crate::unread::Unread;
use osis_base::{BlobId, CommitId, SyncId, WallMs};
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
    fn caught_since(&self, conn: ConnId, s: &SyncId) -> Option<WallMs> {
        self.streams.caught_since(conn, s)
    }
    fn full(&self, at: Source, s: &SyncId) -> bool {
        self.streams.known().full(at, s)
    }
    fn refusing(&self, at: Source, s: &SyncId) -> bool {
        self.streams.known().refusing(at, s)
    }
    fn stranded(&self, s: &SyncId) -> bool {
        self.unread.stranded(s)
    }
}

pub struct Live<'a, 'b> {
    pub cx: &'a mut Cx<'b>,
    pub opens: &'a Opens,
    pub streams: &'a Streams,
    pub read: &'a Read,
    pub unread: &'a Unread,
}

impl Live<'_, '_> {
    fn net(&self) -> NetView<'_> {
        NetView { streams: self.streams, unread: self.unread }
    }
}

impl Net for Live<'_, '_> {
    fn caught_since(&self, conn: ConnId, s: &SyncId) -> Option<WallMs> {
        self.net().caught_since(conn, s)
    }
    fn full(&self, at: Source, s: &SyncId) -> bool {
        self.net().full(at, s)
    }
    fn refusing(&self, at: Source, s: &SyncId) -> bool {
        self.net().refusing(at, s)
    }
    fn stranded(&self, s: &SyncId) -> bool {
        self.net().stranded(s)
    }
}

impl Ground for Live<'_, '_> {
    fn now(&self) -> WallMs {
        self.cx.now
    }
    fn syncs(&mut self) -> Result<Arc<SyncSet>> {
        Ok(Arc::new(SyncSet { ids: self.cx.store.syncs(), ..SyncSet::default() }))
    }
    fn stamped(&mut self, s: &SyncId) -> Result<Vec<BlobId>> {
        Ok(self.cx.store.entries(s)?.into_iter().filter(|e| e.stamp.is_some()).map(|e| e.blob).collect())
    }
    fn knows(&self, at: Source, conn: ConnId, s: &SyncId, b: &BlobId) -> bool {
        self.streams.knows(at, Some(conn), s, b)
    }
    fn reported(&self, conn: ConnId, s: &SyncId) -> Option<Position> {
        self.opens.reported_at(conn, s).map(|(p, _)| *p)
    }
    fn until(&self, conn: ConnId, s: &SyncId) -> Option<Position> {
        self.opens.members(conn).get(s).and_then(|m| m.until)
    }
    fn records_holding(&self, s: &SyncId) -> Result<BTreeSet<RecordId>> {
        self.opens.records_holding(self.cx.store, s)
    }
    fn own_commits(&mut self, s: &SyncId) -> Result<Arc<BTreeSet<CommitId>>> {
        Ok(self.cx.engine.own_commits(s)?)
    }
    fn self_removals(&mut self) -> Result<Arc<BTreeSet<CommitId>>> {
        Ok(self.cx.engine.waiting_removals()?)
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
    fn shared(&mut self, s: &SyncId) -> Result<bool> {
        // own: a node of this account, or this account itself (a peer that proved only the
        // account, its node unproven: a dialer lacking this node's `reach.0`)
        let engine = &mut *self.cx.engine;
        let me = engine.account()?.map(|(p, _)| p);
        self.opens.shared(self.cx.store, s, |t| Some(*t) == me || engine.own_node(t))
    }
    fn removal_done(&mut self, c: &CommitId) -> Result<()> {
        Ok(self.cx.engine.removal_done(c)?)
    }
    fn passes_wanted(&mut self) -> Result<Arc<BTreeMap<SyncId, WallMs>>> {
        Ok(self.cx.engine.passes_wanted()?)
    }
    fn pass_clock(&mut self) -> WallMs {
        self.cx.engine.pass_clock()
    }
    fn note_complete_pass(&mut self, s: &SyncId, began: WallMs) -> Result<()> {
        self.cx.engine.note_complete_pass(s, began)?;
        // the re-seal trigger decides at a complete pass's end (spec/permissions.md §3 Complete
        // pass): the engine re-seals and adds history once every sync ID of S's actor had one
        if let Some(actor) = self.cx.engine.sync_owner(s)? {
            self.cx.engine.reseal_due(&actor)?;
        }
        Ok(())
    }
}
