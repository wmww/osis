//! The product's ground: the engine's facade, the store, opens' members and streams' `known`.
//! Not built (each answers `NotBuilt`): notes/sync-boundary.md (4. `read`, Before read runs in a
//! node) lists each. Read runs only once every call is built (`READY`): a call failing in the
//! middle of a settle fails the node's step, closing every connection.

use super::Why;
use super::ground::{BlobInfo, Facts, Ground, Seen, SrcView};
use crate::opens::Opens;
use crate::session::{Sessions, To};
use crate::store::{Source, Stand};
use crate::status::{NetView, Status};
use crate::streams::Streams;
use crate::unread::Unread;
use crate::types::{Cx, Entry, Error, Result, SourceClass};
use osis_base::memo::Feed;
use osis_base::{BlobId, CommitId, SyncId, WallMs};
use osis_crypto::SigningSecret;
use osis_engine::sync::{BodyMeta, Destruction, MustNot, ReadCredentials};
use osis_label::{Class, DeleteItem};
use osis_proto::Msg;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub struct Live<'a, 'b> {
    pub cx: &'a mut Cx<'b>,
    pub sessions: &'a mut Sessions,
    pub opens: &'a Opens,
    pub streams: &'a Streams,
    pub status: &'a Status,
    pub unread: &'a Unread,
    /// The engine's commits held, followed from read's first settle.
    pub commits: &'a mut Option<Feed<CommitId>>,
}

/// Every ground call is built: read runs (`commits_added` gates it).
const READY: bool = false;

/// The entry this node logs of its own under `s`: stamped where it writes S's head, else
/// deposited.
fn own_entry(cx: &mut Cx, s: &SyncId, blob: BlobId, wrap: crate::types::Wrap, class: Class) -> Result<Entry> {
    let stamp = cx.engine.signers(s, None)?.stamp.map(|w| osis_label::sign_stamp(&w, s, &blob, &wrap, false));
    Ok(Entry { blob, wrap, stamp, deposited: stamp.is_none(), own: true, role: false, class, expires: None })
}

impl Live<'_, '_> {
    fn thing(&mut self, s: &SyncId) -> Result<Option<osis_base::Tid>> {
        Ok(self.cx.engine.sync_holding(s)?.map(|(t, _)| t))
    }
}

impl Ground for Live<'_, '_> {
    fn commits_added(&mut self) -> Result<Vec<CommitId>> {
        if !READY {
            return Err(Error::NotBuilt("read: streams' known and seen, opens' source views, inbox deposits, closure settled, deletes known"));
        }
        match self.commits.as_mut() {
            Some(f) => Ok(f.added()),
            None => {
                *self.commits = Some(self.cx.engine.commit_feed());
                Ok(self.cx.engine.commit_ids())
            }
        }
    }
    fn bodies(&mut self, c: &CommitId) -> Result<Arc<BTreeMap<SyncId, BodyMeta>>> {
        Ok(self.cx.engine.sync_bodies(c)?)
    }
    fn facts(&mut self, s: &SyncId, c: &CommitId) -> Result<Facts> {
        let f = self.cx.engine.read_facts(s, c)?;
        let must_not = f.must_not.map(|m| match m {
            MustNot::Purged => Why::Purged,
            MustNot::StrictSubset => Why::StrictSubset,
            MustNot::CardSuperseded => Why::CardSuperseded,
            MustNot::CardEnded => Why::CardEnded,
        });
        Ok(Facts { body: f.body, must_not, own: f.own, role: f.role, carriers: f.carriers, later_unheld: f.later_unheld, neither: f.neither, missing: f.missing })
    }
    fn fall_mark(&mut self, _s: &SyncId, c: &CommitId) -> Result<u64> {
        Ok(self.cx.engine.body_fall_mark(c)?)
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
    fn reads(&mut self, s: &SyncId) -> Result<bool> {
        Ok(self.cx.engine.sync_holding(s)?.is_some_and(|(_, h)| h == osis_engine::sync::Holding::Read))
    }
    fn closure_settled(&mut self, s: &SyncId) -> Result<bool> {
        let _ = s;
        Err(Error::NotBuilt("engine: a closure's group.0 held as a header only"))
    }
    fn pullable(&mut self, s: &SyncId) -> Result<bool> {
        if self.sessions.conns().into_iter().any(|c| self.opens.members(c).contains_key(s)) {
            return Ok(true);
        }
        Ok(self.cx.engine.publishes_reach()?)
    }
    fn now(&self) -> WallMs {
        self.cx.now
    }
    fn own(&mut self, s: &SyncId, c: &CommitId) -> Result<Vec<Entry>> {
        let mut out = Vec::new();
        for b in self.cx.engine.commit_blobs(c)?.iter() {
            out.extend(self.cx.store.entry(s, b)?);
        }
        Ok(out)
    }
    fn own_tombstones(&mut self, s: &SyncId, c: &CommitId) -> Result<Vec<BlobId>> {
        let mut out = Vec::new();
        for b in self.cx.engine.commit_blobs(c)?.iter() {
            if self.cx.store.tombstone(s, b)?.is_some() {
                out.push(*b);
            }
        }
        Ok(out)
    }
    fn own_empty(&mut self, s: &SyncId) -> Result<bool> {
        Ok(self.cx.store.entries(s)?.is_empty())
    }
    fn blob(&mut self, b: &BlobId) -> Result<Option<BlobInfo>> {
        if self.cx.store.blob_len(b)?.is_none() {
            return Ok(None);
        }
        let (Some(parts), Some(copy)) = (self.cx.engine.blob_parts(b)?, self.cx.engine.blob_copy(b)?) else { return Ok(None) };
        Ok(Some(BlobInfo { parts, copy }))
    }
    fn deletes_known(&mut self, _s: &SyncId) -> Result<bool> {
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
    fn source(&mut self, s: &SyncId, at: &Source) -> Result<Option<SrcView>> {
        let _ = (s, at);
        Err(Error::NotBuilt("opens: one source's view per sync ID, stamped"))
    }
    fn sources_added(&mut self) -> Result<Vec<(SyncId, Source)>> {
        Err(Error::NotBuilt("opens: a feed of source views written"))
    }
    fn seen_added(&mut self) -> Result<Vec<(Source, SyncId, CommitId)>> {
        Err(Error::NotBuilt("streams: a feed of known rows written"))
    }
    fn present_anywhere(&mut self, s: &SyncId, c: &CommitId) -> Result<bool> {
        let _ = (s, c);
        Err(Error::NotBuilt("streams: an entry of a commit present at some source"))
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
        Ok(self.status.heard_out(s, &NetView { streams: self.streams, unread: self.unread }))
    }
    fn stand(&mut self, at: &Source, s: &SyncId, c: &CommitId) -> Result<Option<Stand>> {
        self.cx.store.stand(*at, s, &c.0)
    }
    fn log_own(&mut self, s: &SyncId, c: &CommitId, fresh: bool) -> Result<Option<BlobId>> {
        let class = if self.cx.engine.sync_bodies(c)?.get(s).is_some() { Class::Durable } else { return Ok(None) };
        if !fresh {
            // a held blob of the commit not tombstoned under S, verbatim under a wrap for S
            let homes: Vec<SyncId> = self.cx.engine.sync_bodies(c)?.keys().copied().collect();
            for b in self.cx.engine.commit_blobs(c)?.iter() {
                if self.cx.store.tombstone(s, b)?.is_some() || self.cx.store.blob_len(b)?.is_none() {
                    continue;
                }
                for from in &homes {
                    let Some(e) = self.cx.store.entry(from, b)? else { continue };
                    let Some(wrap) = self.cx.engine.rewrap(c, b, from, &e.wrap, s)? else { continue };
                    let e = own_entry(self.cx, s, *b, wrap, e.class)?;
                    let code = self.cx.store.log(s, e, None, None)?;
                    return Ok((code == osis_proto::Code::OK).then_some(*b));
                }
            }
        }
        let Some((sealed, wrap)) = self.cx.engine.seal_body(s, c, self.cx.rng)? else { return Ok(None) };
        let e = own_entry(self.cx, s, sealed.id, wrap, class)?;
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
    fn deposit(&mut self, at: &SrcView, s: &SyncId, c: &CommitId, b: &BlobId) -> Result<()> {
        let _ = (at, s, c, b);
        Err(Error::NotBuilt("inbox: Deposit items (relay, or a fresh encryption by seal_body)"))
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
}
