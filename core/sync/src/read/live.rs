//! The product's ground: the engine's facade, the store, opens' members and streams' `known`.
//! Not built (each answers `NotBuilt`, so `Read` does nothing until it is): the engine's
//! held-commit feed (a `Feed` over the commits it holds), the facts beside `BodyFacts`
//! (`ground::Facts`), a body's fall mark (the facade's is per aspect; read needs it per commit),
//! the store's entries and tombstones by commit, `known` by commit and whole (streams), heard
//! out (status). Deposits and relays are inbox's Deposit items: not sent until inbox takes them.

use super::ground::{Facts, Ground, Seen, SrcView};
use crate::opens::Opens;
use crate::session::{Sessions, To};
use crate::store::{Source, Stand};
use crate::streams::Streams;
use crate::types::{Cx, Entry, Error, Result, SourceClass};
use osis_base::{BlobId, CommitId, SyncId, WallMs};
use osis_crypto::SigningSecret;
use osis_engine::sync::{BodyMeta, Destruction, ReadCredentials};
use osis_label::{Class, DeleteItem};
use osis_proto::Msg;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub struct Live<'a, 'b> {
    pub cx: &'a mut Cx<'b>,
    pub sessions: &'a mut Sessions,
    pub opens: &'a Opens,
    pub streams: &'a Streams,
}

impl Live<'_, '_> {
    fn thing(&mut self, s: &SyncId) -> Result<Option<osis_base::Tid>> {
        Ok(self.cx.engine.sync_set()?.ids.get(s).map(|(t, _)| *t))
    }
}

impl Ground for Live<'_, '_> {
    fn commits_added(&mut self) -> Result<Vec<CommitId>> {
        Err(Error::NotBuilt("read: the engine's held-commit feed"))
    }
    fn bodies(&mut self, c: &CommitId) -> Result<Arc<BTreeMap<SyncId, BodyMeta>>> {
        Ok(self.cx.engine.sync_bodies(c)?)
    }
    fn facts(&mut self, s: &SyncId, c: &CommitId) -> Result<Facts> {
        let _ = self.cx.engine.body_facts(s, c)?;
        Err(Error::NotBuilt("read: facts beside BodyFacts"))
    }
    fn fall_mark(&mut self, s: &SyncId, c: &CommitId) -> Result<u64> {
        let _ = (s, c);
        Err(Error::NotBuilt("read: fall mark per commit"))
    }
    fn credentials(&mut self, s: &SyncId) -> Result<Option<Arc<ReadCredentials>>> {
        Ok(self.cx.engine.read_credentials(s)?)
    }
    fn destruction(&mut self, s: &SyncId) -> Result<Option<Arc<Destruction>>> {
        match self.thing(s)? {
            Some(t) => Ok(self.cx.engine.destruction(&t)?),
            None => Ok(None),
        }
    }
    fn now(&self) -> WallMs {
        self.cx.now
    }
    fn own(&mut self, s: &SyncId, c: &CommitId) -> Result<Vec<Entry>> {
        let _ = (s, c);
        Err(Error::NotBuilt("store: entries by commit"))
    }
    fn own_tombstones(&mut self, s: &SyncId, c: &CommitId) -> Result<Vec<BlobId>> {
        let _ = (s, c);
        Err(Error::NotBuilt("store: tombstones by commit"))
    }
    fn own_empty(&mut self, s: &SyncId) -> Result<bool> {
        let _ = s;
        Ok(self.cx.store.entries(s)?.is_empty())
    }
    fn deletes_known(&mut self, s: &SyncId) -> Result<bool> {
        let _ = s;
        Err(Error::NotBuilt("store: deletes seen per sync ID"))
    }
    fn sources(&mut self, s: &SyncId) -> Result<Arc<Vec<SrcView>>> {
        let mut out = Vec::new();
        for conn in self.sessions.conns() {
            if let Some(m) = self.opens.members(conn).get(s) {
                let at = self.opens.record(conn).map_or(Source::Conn(conn), Source::Record);
                out.push(SrcView { at, conn, store: m.class == SourceClass::Store, head: m.step, full: false, role_unheld: false });
            }
        }
        Ok(Arc::new(out))
    }
    fn seen(&mut self, at: &Source, s: &SyncId, c: &CommitId) -> Result<Seen> {
        let _ = (at, s, c, self.streams);
        Err(Error::NotBuilt("streams: known by commit"))
    }
    fn seen_all(&mut self, at: &Source, s: &SyncId) -> Result<BTreeSet<BlobId>> {
        let _ = (at, s);
        Err(Error::NotBuilt("streams: known by source"))
    }
    fn heard_out(&mut self, s: &SyncId) -> Result<bool> {
        let _ = s;
        Err(Error::NotBuilt("status: heard out"))
    }
    fn stand(&mut self, at: &Source, s: &SyncId, c: &CommitId) -> Result<Option<Stand>> {
        self.cx.store.stand(*at, s, &c.0)
    }
    fn log_own(&mut self, s: &SyncId, c: &CommitId) -> Result<Option<BlobId>> {
        let Some((sealed, wrap)) = self.cx.engine.seal_body(s, c, self.cx.rng)? else { return Ok(None) };
        let e = Entry { blob: sealed.id, wrap, stamp: None, deposited: false, own: true, class: Class::Durable, expires: None };
        let code = self.cx.store.log(s, e, Some(sealed.blob), None)?;
        Ok((code == osis_proto::Code::OK).then_some(sealed.id))
    }
    fn drop_own(&mut self, s: &SyncId, b: &BlobId, c: &CommitId) -> Result<()> {
        self.cx.store.drop_entry(s, b, c.0.to_vec())?;
        Ok(())
    }
    fn lift(&mut self, s: &SyncId, b: &BlobId) -> Result<()> {
        self.cx.store.lift_tombstone(s, b)?;
        Ok(())
    }
    fn delete(&mut self, at: &SrcView, s: &SyncId, b: &BlobId, key: &SigningSecret) -> Result<()> {
        if let Some(session) = self.sessions.get_mut(at.conn) {
            session.request(To::Read, Msg::Delete { id: 0, sync_id: *s, items: vec![DeleteItem::sign(key, s, *b)] });
        }
        Ok(())
    }
    fn deposit(&mut self, at: &SrcView, s: &SyncId, b: &BlobId) -> Result<()> {
        let _ = (at, s, b);
        Ok(())
    }
    fn set_stand(&mut self, at: &Source, s: &SyncId, c: &CommitId, stand: &Stand) -> Result<()> {
        self.cx.store.set_stand(*at, s, &c.0, Some(stand))
    }
    fn forget(&mut self, s: &SyncId) -> Result<()> {
        let thing = self.thing(s)?;
        self.cx.store.shred(s)?;
        if let Some(t) = thing {
            self.cx.engine.forget_destroyed(&t)?;
        }
        Ok(())
    }
    fn leave(&mut self, s: &SyncId) -> Result<()> {
        self.cx.store.shred(s)
    }
}
