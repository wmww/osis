//! The product's ground: the engine's facade, the store, the sources of each S (`views`, as opens
//! moved them) and streams' `known` (notes/sync-read.md, The ground in a node). A call
//! failing in the middle of a settle fails the node's step, closing every connection.

use super::Why;
use super::ground::{BlobInfo, Facts, Ground, PieceAt, RecordsMissing, Seen, SrcView};
use osis_engine::retention::freed::Freed;
use osis_engine::sync::PieceLink;
use osis_label::StepId;
use crate::opens::Opens;
use crate::session::{Sessions, To};
use crate::store::{Source, Stand};
use crate::status::{NetView, Status};
use crate::streams::Streams;
use crate::unread::Unread;
use crate::types::{ConnId, Cx, Entry, Result};
use osis_base::memo::Feed;
use osis_base::{BlobId, CommitId, SyncId, Tid, WallMs};
use osis_crypto::SigningSecret;
use osis_engine::sync::{BodyMeta, Destruction, HeldBlob, MustNot, ReadCredentials};
use osis_label::{Class, DeleteItem};
use osis_proto::Msg;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Read's cursors over the rows other modules write: streams' `known` and the source views.
#[derive(Clone, Default)]
pub struct Feeds {
    known: Option<Feed<crate::streams::KnownRow>>,
    views: Option<Feed<super::views::Row>>,
    freed: Option<Feed<(BlobId, Tid)>>,
}

pub struct Live<'a, 'b> {
    pub cx: &'a mut Cx<'b>,
    pub sessions: &'a mut Sessions,
    pub opens: &'a Opens,
    pub streams: &'a Streams,
    pub status: &'a Status,
    pub unread: &'a Unread,
    /// The engine's commits held, followed from read's first settle.
    pub commits: &'a mut Option<Feed<CommitId>>,
    pub views: &'a super::views::Views,
    pub feeds: &'a mut Feeds,
    /// Entries to fetch again, per connection (`Act::Fetch`): the driver hands them to streams.
    pub fetches: &'a mut Vec<(ConnId, SyncId, BlobId)>,
}


/// The entry this node logs of its own under `s`: stamped where it writes S's head, else
/// deposited.
fn own_entry(cx: &mut Cx, s: &SyncId, blob: BlobId, wrap: crate::types::Wrap, class: Class) -> Result<Entry> {
    let stamp = cx.engine.signers(s, None)?.stamp.map(|w| osis_label::sign_stamp(&w, s, &blob, &wrap, false));
    Ok(Entry { blob, wrap, stamp, deposited: stamp.is_none(), own: true, role: false, class, expires: None })
}

impl Live<'_, '_> {
    fn thing(&mut self, s: &SyncId) -> Result<Option<osis_base::Tid>> {
        Ok(self.cx.store.synced(s).map(|(t, _)| t))
    }

    /// `c`'s body under `s` as a fresh encryption (logging again, a deposit, a body with no held
    /// encryption): `Engine::seal_body` given every blob of `c` the store holds bytes of, each
    /// with an entry's wrap, tombstoned under `s` or not (spec/crypto.md §5 Passing on: what
    /// this node may not encrypt under an epoch of its choosing goes as the section it came in).
    /// The only place read makes a fresh encryption of a body.
    fn fresh(&mut self, s: &SyncId, c: &CommitId) -> Result<Option<(osis_engine::labeling::Sealed, crate::types::Wrap)>> {
        let mut held = Vec::new();
        for b in self.cx.engine.commit_blobs(c)?.iter() {
            let Some(bytes) = self.cx.store.bytes(b)? else { continue };
            let Some(e) = self.cx.store.naming(b)?.into_iter().find_map(|x| self.cx.store.entry(&x, b).ok().flatten().map(|e| (x, e))) else { continue };
            held.push(HeldBlob { sync_id: e.0, wrap: e.1.wrap, bytes });
        }
        Ok(self.cx.engine.seal_body(s, c, &held, self.cx.rng)?)
    }
}

impl Live<'_, '_> {
    /// Own entry `b` of `c` logged under S (`code`): one of an ephemeral commit from another
    /// node counts toward S's memory cap at what the commit costs held here
    /// (spec/sync-compaction.md §2 Caps).
    fn logged(&mut self, s: &SyncId, c: &CommitId, b: BlobId, code: osis_proto::Code) -> Result<Option<BlobId>> {
        if code != osis_proto::Code::OK {
            return Ok(None);
        }
        if self.cx.engine.holds_memory(c) && !self.cx.engine.read_facts(s, c)?.own {
            let n = self.cx.engine.memory_charge(c)?;
            self.cx.store.set_memory_charge(s, &b, n);
        }
        Ok(Some(b))
    }
}

impl Ground for Live<'_, '_> {
    fn commits_added(&mut self) -> Result<Vec<CommitId>> {
        // the feeds start with the first settle: what each covers before is judged then
        if self.feeds.known.is_none() {
            self.feeds.known = Some(self.streams.known().feed());
            self.feeds.views = Some(self.views.feed());
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
            MustNot::CardSuperseded => Why::CardSuperseded,
            MustNot::CardEnded => Why::CardEnded,
        });
        Ok(Facts { body: f.body, must_not, own: f.own, repair_fresh: f.repair_fresh, role: f.role, carriers: f.carriers, later_unheld: f.later_unheld, missing: f.missing })
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
        Ok(self.cx.store.holding(s) == Some(osis_engine::sync::Holding::Read))
    }
    fn closure_settled(&mut self, s: &SyncId) -> Result<bool> {
        match self.thing(s)? {
            Some(t) => Ok(self.cx.engine.closure_whole(&t)?),
            None => Ok(false),
        }
    }
    fn pullable(&mut self, s: &SyncId) -> Result<bool> {
        // a source of S up now (stamped: a source joining judges again)
        if self.views.any(s) {
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
    fn dropped(&mut self, b: &BlobId) -> Result<bool> {
        Ok(self.cx.engine.blob_dropped(b)?)
    }
    fn strict_subset(&mut self, s: &SyncId, b: &BlobId, held: &BTreeSet<BlobId>) -> Result<bool> {
        Ok(self.cx.engine.strict_subset(s, b, held)?)
    }
    fn neither(&mut self, s: &SyncId, c: &CommitId, there: &BTreeSet<BlobId>) -> Result<bool> {
        Ok(self.cx.engine.neither(s, c, there)?)
    }
    fn deletes_known(&mut self, s: &SyncId) -> Result<bool> {
        self.cx.store.deletes_known(s)
    }
    fn sources(&mut self, s: &SyncId) -> Result<Arc<Vec<SrcView>>> {
        let mut out = Vec::new();
        for at in self.views.of(s) {
            out.extend(self.source(s, &at)?);
        }
        Ok(Arc::new(out))
    }
    fn source(&mut self, s: &SyncId, at: &Source) -> Result<Option<SrcView>> {
        let Some(mut v) = self.views.get(s, at) else { return Ok(None) };
        let known = self.streams.known();
        v.head = known.head(*at, s);
        v.full = known.full(*at, s);
        Ok(Some(v))
    }
    fn sources_added(&mut self) -> Result<Vec<(SyncId, Source)>> {
        Ok(self.feeds.views.as_mut().map(|f| f.added()).unwrap_or_default().into_iter().map(|(_, s, at)| (s, at)).collect())
    }
    fn seen_added(&mut self) -> Result<Vec<(Source, SyncId, CommitId)>> {
        let mut out = Vec::new();
        // a blob this node never opened or sealed names no commit here: it is pulled, and its
        // commit known, once opened
        for (at, s, b) in self.feeds.known.as_mut().map(|f| f.added()).unwrap_or_default() {
            if let Some(c) = self.cx.engine.blob_commit(&b)? {
                out.push((at, s, c));
            }
        }
        Ok(out)
    }
    fn present_anywhere(&mut self, s: &SyncId, c: &CommitId) -> Result<bool> {
        let known = self.streams.known();
        Ok(self.cx.engine.commit_blobs(c)?.iter().any(|b| known.present(s, b)))
    }
    fn seen(&mut self, at: &Source, s: &SyncId, c: &CommitId) -> Result<Seen> {
        let mut seen = Seen::default();
        for b in self.cx.engine.commit_blobs(c)?.iter() {
            if self.streams.known().knows(*at, s, b) {
                seen.present.insert(*b);
            } else if self.cx.store.seen_deleted(*at, s, b)? {
                seen.deleted.insert(*b);
            }
        }
        Ok(seen)
    }
    fn seen_all(&mut self, at: &Source, s: &SyncId) -> Result<BTreeSet<BlobId>> {
        Ok(self.streams.known().list(*at, s)?.into_iter().collect())
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
                if self.cx.store.tombstone(s, b)?.is_some() || self.cx.store.blob_len(b)?.is_none() || self.cx.engine.blob_dropped(b)? {
                    continue;
                }
                for from in &homes {
                    let Some(e) = self.cx.store.entry(from, b)? else { continue };
                    let Some(wrap) = self.cx.engine.rewrap(c, b, from, &e.wrap, s)? else { continue };
                    let e = own_entry(self.cx, s, *b, wrap, e.class)?;
                    let code = self.cx.store.log(s, e, None, None)?;
                    return self.logged(s, c, *b, code);
                }
            }
        }
        let Some((sealed, wrap)) = self.fresh(s, c)? else { return Ok(None) };
        let e = own_entry(self.cx, s, sealed.id, wrap, class)?;
        let code = self.cx.store.log(s, e, Some(sealed.blob), None)?;
        self.logged(s, c, sealed.id, code)
    }
    fn drop_own(&mut self, s: &SyncId, b: &BlobId, c: &CommitId) -> Result<()> {
        self.cx.store.drop_entry(s, b, c.0.to_vec())?;
        Ok(())
    }
    fn lift(&mut self, s: &SyncId, b: &BlobId) -> Result<()> {
        self.cx.store.lift_tombstone(s, b)?;
        Ok(())
    }
    fn fetch(&mut self, at: &SrcView, s: &SyncId, b: &BlobId) -> Result<()> {
        self.fetches.push((at.conn, *s, *b));
        Ok(())
    }
    fn delete(&mut self, at: &SrcView, s: &SyncId, b: &BlobId, key: &SigningSecret) -> Result<()> {
        if let Some(session) = self.sessions.get_mut(at.conn) {
            session.request(To::Read, Msg::Delete { id: 0, sync_id: *s, items: vec![DeleteItem::sign(key, s, *b)] });
        }
        Ok(())
    }
    fn deposit(&mut self, at: &SrcView, s: &SyncId, c: &CommitId, b: &BlobId) -> Result<()> {
        let Some(e) = self.cx.store.entry(s, b)? else { return Ok(()) };
        // a deposited own entry is offered to every store source of S (inbox's offers)
        if e.deposited {
            return Ok(());
        }
        // stamped under the source's head write key: it pulls it as it is
        let write = at.head.and_then(|h| self.cx.store.path(s).ok().flatten().and_then(|p| p.steps.iter().find(|(st, _)| st.id() == h).map(|(st, _)| st.keys.write)));
        if let (Some(w), Some(stamp)) = (write, e.stamp)
            && osis_label::verify_stamp(&w, s, b, &e.wrap, &stamp).unwrap_or(false)
        {
            return Ok(());
        }
        // else a fresh encryption, deposited: offered as it is logged
        let Some((sealed, wrap)) = self.fresh(s, c)? else { return Ok(()) };
        let entry = Entry { blob: sealed.id, wrap, stamp: None, deposited: true, own: true, role: false, class: e.class, expires: None };
        self.cx.store.log(s, entry, Some(sealed.blob), None)?;
        Ok(())
    }
    fn set_stand(&mut self, at: &Source, s: &SyncId, c: &CommitId, stand: &Stand) -> Result<()> {
        self.cx.store.set_stand(*at, s, &c.0, Some(stand))
    }
    fn records_missing(&mut self, s: &SyncId) -> Result<RecordsMissing> {
        let mut out = RecordsMissing { records: (*self.cx.engine.certificate_records(s)?).clone(), gone: BTreeSet::new() };
        for (b, tids) in self.cx.engine.record_blobs(s)?.iter() {
            match self.cx.store.entry(s, b)?.is_some_and(|e| e.own) {
                true => out.records.retain(|t| !tids.contains(t)),
                false => {
                    out.gone.insert(*b);
                }
            }
        }
        Ok(out)
    }
    fn forget_record_blobs(&mut self, s: &SyncId, gone: &BTreeSet<osis_base::BlobId>) -> Result<()> {
        for b in gone {
            self.cx.engine.forget_record_blob(s, b)?;
        }
        Ok(())
    }
    fn step_ready(&mut self, s: &SyncId) -> Result<bool> {
        let Some(needs) = self.cx.engine.due_step(s)? else { return Ok(false) };
        for c in needs.iter() {
            let mut logged = false;
            for b in self.cx.engine.commit_blobs(c)?.iter() {
                logged |= self.cx.store.entry(s, b)?.is_some_and(|e| e.stamp.is_some());
            }
            if !logged {
                return Ok(false);
            }
        }
        Ok(true)
    }
    fn issue_step(&mut self, s: &SyncId) -> Result<bool> {
        Ok(self.cx.engine.issue_due_step(s)?.is_some())
    }
    fn log_records(&mut self, s: &SyncId, records: &BTreeSet<osis_base::Tid>) -> Result<()> {
        let Some((blob, bytes, wrap)) = self.cx.engine.seal_records(s, records, self.cx.rng)? else { return Ok(()) };
        let e = own_entry(self.cx, s, blob, wrap, Class::Durable)?;
        self.cx.store.log(s, e, Some(bytes), None)?;
        Ok(())
    }
    fn piece_roots(&mut self, s: &SyncId, c: &CommitId) -> Result<Arc<Vec<PieceLink>>> {
        let Some(parts) = self.cx.engine.sync_bodies(c)?.get(s).map(|m| m.parts.clone()) else { return Ok(Arc::default()) };
        Ok(Arc::new(self.cx.engine.piece_roots(c, &parts)?))
    }
    fn piece_below(&mut self, p: &PieceLink) -> Result<Option<Arc<Vec<PieceLink>>>> {
        Ok(self.cx.engine.piece_below(p)?)
    }
    fn piece(&mut self, s: &SyncId, b: &BlobId) -> Result<PieceAt> {
        Ok(match self.cx.store.entry(s, b)? {
            Some(e) if e.own => PieceAt::Own,
            Some(_) => PieceAt::Peer,
            None if self.cx.store.tombstone(s, b)?.is_some() => PieceAt::Tombstoned,
            None => PieceAt::Absent,
        })
    }
    fn piece_shown(&mut self, at: &Source, s: &SyncId, b: &BlobId) -> Result<bool> {
        Ok(self.streams.known().knows(*at, s, b))
    }
    fn piece_deleted(&mut self, at: &Source, s: &SyncId, b: &BlobId) -> Result<bool> {
        self.cx.store.seen_deleted(*at, s, b)
    }
    fn log_piece(&mut self, s: &SyncId, b: &BlobId) -> Result<()> {
        if let Some(e) = self.cx.store.entry(s, b)? {
            // a peer's entry of it (its wrap and stamp as they came) becomes own
            if !e.own {
                self.cx.store.log(s, Entry { own: true, ..e }, None, None)?;
                self.cx.store.uncharge(s, b)?;
            }
            return Ok(());
        }
        let Some(bytes) = self.cx.store.bytes(b)? else { return Ok(()) };
        let wrap = osis_crypto::filler_wrap(&mut *self.cx.rng);
        // class and expiry come from the bytes' prefix
        let e = own_entry(self.cx, s, *b, wrap, Class::Durable)?;
        self.cx.store.log(s, e, Some(bytes), None)?;
        Ok(())
    }
    fn take_piece(&mut self, s: &SyncId, b: &BlobId) -> Result<()> {
        let _ = s;
        if let Some(bytes) = self.cx.store.bytes(b)? {
            self.cx.engine.take_piece(b, bytes)?;
        }
        Ok(())
    }
    fn repair(&mut self, c: &CommitId, b: &BTreeSet<BlobId>) -> Result<()> {
        let Some(h) = self.cx.engine.header(c) else { return Ok(()) };
        let things: BTreeSet<Tid> = h.aspects.iter().map(|a| a.tid).collect();
        // a rewrite refused (no write here now, a value too large) leaves it: a store failure fails
        match self.cx.engine.relink(b, &things, &mut |_, _| true) {
            Err(e) if osis_base::Classified::class(&e) == osis_base::ErrorClass::Local => Err(e.into()),
            _ => Ok(()),
        }
    }
    fn freed_added(&mut self) -> Result<Vec<(BlobId, Tid)>> {
        match self.feeds.freed.as_mut() {
            Some(f) => Ok(f.added()),
            None => {
                self.feeds.freed = Some(self.cx.engine.freed_feed());
                Ok(self.cx.engine.freed_rows())
            }
        }
    }
    fn freed_link(&mut self, b: &BlobId, t: &Tid) -> Result<bool> {
        Ok(self.cx.engine.freed_link(b, t).is_some())
    }
    fn carrying(&mut self, t: &Tid) -> Result<BTreeSet<SyncId>> {
        Ok(self.cx.engine.carrying(t)?)
    }
    fn drop_piece(&mut self, s: &SyncId, b: &BlobId) -> Result<()> {
        self.cx.store.drop_entry(s, b, Vec::new())?;
        Ok(())
    }
    fn delete_freed(&mut self, at: &SrcView, s: &SyncId, head: &StepId, b: &BlobId, t: &Tid) -> Result<()> {
        let Some(f) = self.cx.engine.freed_link(b, t) else { return Ok(()) };
        let f: &Freed = &f;
        let Some(keys) = self.cx.engine.read_credentials(s)?.and_then(|c| c.keys.get(head).cloned()) else { return Ok(()) };
        let blob = f.link.blob;
        let item = match (f.borne, &keys.delete) {
            (true, Some(d)) => DeleteItem::sign(d, s, blob),
            _ => {
                let dks = self.cx.engine.freed_delete_secrets(f);
                let refs: Vec<(osis_label::Level, &osis_crypto::DeleteSecret)> = dks.iter().map(|(l, d)| (*l, d)).collect();
                let levels: Vec<osis_label::Level> = refs.iter().map(|x| x.0).collect();
                let key = match osis_label::key_for_levels(&levels) {
                    Ok(osis_crypto::LabelRole::Write) => keys.write.clone(),
                    Ok(osis_crypto::LabelRole::Sync) if keys.sync_established => keys.sync.clone(),
                    _ => None,
                };
                let (Some(key), false) = (key, refs.is_empty()) else { return Ok(()) };
                let (salt, blind) = f.blinding();
                let Ok(item) = DeleteItem::sign_by(&key, &refs, &salt, &blind, s, blob) else { return Ok(()) };
                item
            }
        };
        if let Some(session) = self.sessions.get_mut(at.conn) {
            session.request(To::Read, Msg::Delete { id: 0, sync_id: *s, items: vec![item] });
        }
        Ok(())
    }
    fn freed_done(&mut self, b: &BlobId, t: &Tid) -> Result<()> {
        Ok(self.cx.engine.freed_done(&[(*t, *b)])?)
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
