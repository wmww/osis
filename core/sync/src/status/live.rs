//! The product's ground: the engine's facade, the store, opens, streams, read and unread. Not
//! built (each answers `NotBuilt`, so that part of status does nothing until it is): the store's
//! own entries by commit (held elsewhere), the sync IDs the engine wants a complete pass of
//! (`passes_wanted`, proposed facade call: the engine's rules waiting on a pass read the passes it
//! is told of by `note_complete_pass`).

use super::{Ground, Net};
use crate::opens::Opens;
use crate::read::{Read, Verdict};
use crate::store::Source;
use crate::streams::Streams;
use crate::types::{ConnId, Cx, Error, Position, RecordId, Result};
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
    fn sync_set(&mut self) -> Result<Arc<SyncSet>> {
        Ok(self.cx.engine.sync_set()?)
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
    fn records_holding(&self, s: &SyncId) -> BTreeSet<RecordId> {
        self.opens.records_holding(s)
    }
    fn own_commits(&mut self, s: &SyncId) -> Result<Arc<BTreeSet<CommitId>>> {
        Ok(self.cx.engine.own_commits(s)?)
    }
    fn self_removals(&mut self) -> Result<Arc<BTreeSet<CommitId>>> {
        Ok(self.cx.engine.waiting_held_elsewhere()?)
    }
    fn verdict(&self, s: &SyncId, c: &CommitId) -> Option<Verdict> {
        self.read.verdict(s, c)
    }
    fn own_entries(&mut self, s: &SyncId, c: &CommitId) -> Result<Vec<BlobId>> {
        let _ = (s, c);
        Err(Error::NotBuilt("store: own entries by commit"))
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
    fn held_elsewhere(&mut self, c: &CommitId) -> Result<()> {
        Ok(self.cx.engine.held_elsewhere(c)?)
    }
    fn passes_wanted(&mut self) -> Result<Arc<BTreeMap<SyncId, WallMs>>> {
        Err(Error::NotBuilt("engine: passes_wanted (sync IDs wanting a complete pass)"))
    }
    fn note_complete_pass(&mut self, s: &SyncId, began: WallMs) -> Result<()> {
        Ok(self.cx.engine.note_complete_pass(s, began)?)
    }
}
