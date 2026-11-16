//! The product's ground: the engine's facade, the store, the sources of each S (`views`, as opens
//! moved them) and streams' `known` (notes/sync-read.md, The ground in a node). A call
//! failing in the middle of a settle fails the node's step, closing every connection.

use super::Why;
use super::ground::{BlobInfo, CertBlobsMissing, Facts, Ground, PieceAt, Seen, SrcView};
use osis_engine::sync::PieceLink;
use osis_blob::StepId;
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
use osis_engine::sync::{BodyMeta, CertKind, HeldBlob, MustNot, ReadCredentials};
use osis_blob::{Class, DeleteItem};
use osis_proto::Msg;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Read's cursors over the rows other modules write: streams' `known` and the source views.
#[derive(Clone, Default)]
pub struct Feeds {
    known: Option<Feed<crate::streams::KnownRow>>,
    views: Option<Feed<super::views::Row>>,
    freed: Option<Feed<(BlobId, Tid)>>,
    lists: Option<Feed<(Tid, CommitId)>>,
    /// The own store's entries, the blobs coming to name a commit and the commits coming to be
    /// held (`entries_added`).
    entries: Option<EntryFeeds>,
    syncs: Option<Feed<SyncId>>,
}

/// `Feeds::entries`: the store's entries, blobs opened or sealed, commits held.
type EntryFeeds = (Feed<(SyncId, BlobId)>, Feed<BlobId>, Feed<CommitId>);

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


/// The write key of the head S's store serves, where this node holds it (established): what it
/// stamps under. The served head, not the one `sync.0` records: the store's stream names a head
/// (its head event) before any stamp under it, so a reader that holds the step's commit before
/// it applies the stamp knows the key.
fn stamp_key(cx: &mut Cx, s: &SyncId) -> Result<Option<SigningSecret>> {
    let Some(head) = cx.store.head_id(s)? else { return Ok(None) };
    Ok(cx.engine.read_credentials(s)?.and_then(|c| c.keys.get(&head).and_then(|k| k.write.clone())))
}

/// The entry this node logs of its own under `s`: stamped where it writes S's served head, else
/// deposited.
fn own_entry(cx: &mut Cx, s: &SyncId, blob: BlobId, wrap: crate::types::Wrap, class: Class) -> Result<Entry> {
    let stamp = stamp_key(cx, s)?.map(|w| osis_blob::sign_stamp(&w, s, &blob, &wrap, false));
    Ok(Entry { blob, wrap, stamp, deposited: stamp.is_none(), own: true, role: false, class, expires: None })
}

impl Live<'_, '_> {
    /// Of `at`, the read sync IDs whose own store holds an entry of blob `b` (all of them when
    /// `None`), each with `b`'s commit where this node holds it (`entries_added`).
    fn entries_of(&mut self, b: &BlobId, at: Option<SyncId>, out: &mut Vec<(SyncId, CommitId)>) -> Result<()> {
        let Some(c) = self.cx.engine.blob_commit(b) else { return Ok(()) };
        if !self.cx.engine.holds_commit(&c) {
            return Ok(());
        }
        let ids = match at {
            Some(s) if self.cx.store.entry(&s, b)?.is_some() => vec![s],
            Some(_) => Vec::new(),
            None => self.cx.store.naming(b)?,
        };
        for s in ids {
            if self.cx.store.holding(&s) == Some(osis_engine::sync::Holding::Read) {
                out.push((s, c));
            }
        }
        Ok(())
    }

    /// S's things, as this node syncs S.
    fn things(&mut self, s: &SyncId) -> std::collections::BTreeSet<Tid> {
        self.cx.store.synced(s).map(|(t, _)| t).unwrap_or_default()
    }

    /// Entry `e` of S is stamped as this node logs it now: under its served head's write key
    /// where it holds it (`stamp_key`, the key `own_entry` and `restamp` sign with, so a
    /// restamped entry stands at once), any entry anywhere else.
    fn under_head(&mut self, s: &SyncId, e: &Entry) -> Result<bool> {
        let Some(w) = stamp_key(self.cx, s)? else { return Ok(true) };
        Ok(e.stamp.is_some() && self.cx.store.stamp_under(s, &e.blob, &[w.verifying_key()])?)
    }

    /// The parents of the recorded steps of S whose epochs depend on role commit `c`
    /// (`Engine::step_needs`), earliest first: an entry of `c` keeps a stamp under one, so a
    /// source standing there takes it before the step is registered (spec/sync-ids.md §6 Steps).
    fn step_parents(&mut self, s: &SyncId, c: &CommitId) -> Result<Vec<osis_blob::Step>> {
        if !self.cx.engine.read_facts(s, c)?.role {
            return Ok(Vec::new());
        }
        let Some(path) = self.cx.store.path(s)? else { return Ok(Vec::new()) };
        let mut out = Vec::new();
        for w in path.steps.windows(2) {
            let [(parent, _), (step, _)] = w else { continue };
            if self.cx.engine.step_needs(s, &step.id())?.contains(c) {
                out.push(parent.clone());
            }
        }
        Ok(out)
    }

    /// Entry `e` is of role commit `c` that a recorded step of S registers, stamped under that
    /// step's parent (`step_parents`).
    fn registers_step(&mut self, s: &SyncId, c: &CommitId, e: &Entry) -> Result<bool> {
        if e.stamp.is_none() {
            return Ok(false);
        }
        let keys: Vec<_> = self.step_parents(s, c)?.iter().map(|p| p.keys.write).collect();
        self.cx.store.stamp_under(s, &e.blob, &keys)
    }

    /// `c`'s body under `s` as a fresh encryption (logging again, a deposit, a body with no held
    /// encryption): `Engine::seal_body` given every blob of `c` the store holds bytes of, each
    /// with an entry's wrap, tombstoned under `s` or not (spec/crypto.md §5 Passing on: what
    /// this node may not encrypt under an epoch of its choosing goes as the section it came in).
    /// The only place read makes a fresh encryption of a body.
    fn fresh(&mut self, s: &SyncId, c: &CommitId) -> Result<Option<(osis_engine::sync_ids::Sealed, crate::types::Wrap)>> {
        let mut held = Vec::new();
        for (b, x, e) in self.held_blobs(c)? {
            let Some(bytes) = self.cx.store.bytes(&b)? else { continue };
            held.push(HeldBlob { sync_id: x, wrap: e.wrap, bytes });
        }
        Ok(self.cx.engine.seal_body(s, c, &held, self.cx.rng)?)
    }

    /// The sync IDs with an entry of blob `b` that carry a body of `c` (`Engine::sync_body`), in
    /// order.
    fn homes_naming(&mut self, b: &BlobId, c: &CommitId) -> Result<Vec<SyncId>> {
        let mut named = self.cx.store.naming(b)?;
        named.sort_unstable();
        named.dedup();
        let mut out = Vec::new();
        for x in named {
            if self.cx.engine.sync_body(&x, c)?.is_some() {
                out.push(x);
            }
        }
        Ok(out)
    }

    /// The blobs of `c` opened or sealed here whose bytes the store holds, each with an entry
    /// naming it under a sync ID read here that carries a body of `c` (so its wrap opens here):
    /// what a fresh encryption carries and a verbatim log passes on, and so what
    /// `Engine::may_log` reads (one truth: what this node may log is what it can).
    fn held_blobs(&mut self, c: &CommitId) -> Result<Vec<(BlobId, SyncId, Entry)>> {
        let mut out = Vec::new();
        for b in self.cx.engine.commit_blobs(c)?.iter() {
            // the entry first: its row moves when the bytes arrive, so a reader follows them; a
            // sync ID's body asked per sync ID naming the blob, never every sync ID's
            let mut found = None;
            for x in self.homes_naming(b, c)? {
                if let Some(e) = self.cx.store.entry(&x, b).ok().flatten() {
                    found = Some((x, e));
                    break;
                }
            }
            let Some((x, e)) = found else { continue };
            if self.cx.store.blob_len(b)?.is_none() {
                continue;
            }
            out.push((*b, x, e));
        }
        Ok(out)
    }
}

impl Ground for Live<'_, '_> {
    fn commits_added(&mut self) -> Vec<CommitId> {
        // the feeds start with the first settle: what each covers before is judged then
        if self.feeds.views.is_none() {
            self.feeds.views = Some(self.views.feed());
            self.feeds.syncs = Some(self.cx.store.syncs_feed());
        }
        match self.commits.as_mut() {
            Some(f) => f.added(),
            None => {
                *self.commits = Some(self.cx.engine.commit_feed());
                self.cx.engine.commit_ids()
            }
        }
    }
    fn place(&mut self) -> u64 {
        self.cx.engine.pass_place()
    }
    fn passed(&mut self, s: &SyncId, since: u64) -> bool {
        self.status.passed_since(s, since)
    }
    fn unlog(&mut self, s: &SyncId, b: &BlobId) -> Result<()> {
        self.cx.store.unlog_entry(s, b)?;
        Ok(())
    }
    fn entries_added(&mut self) -> Result<Vec<(SyncId, CommitId)>> {
        let mut out = Vec::new();
        let Some((entries, blobs, commits)) = self.feeds.entries.as_mut() else {
            // a start: every entry of every held commit
            self.feeds.entries = Some((self.cx.store.entry_feed(), self.cx.engine.blob_feed(), self.cx.engine.commit_feed()));
            for c in self.cx.engine.commit_ids() {
                for b in self.cx.engine.commit_blobs(&c)?.iter() {
                    self.entries_of(b, None, &mut out)?;
                }
            }
            return Ok(out);
        };
        let (entries, blobs, commits) = (entries.added(), blobs.added(), commits.added());
        for (s, b) in entries {
            self.entries_of(&b, Some(s), &mut out)?;
        }
        for b in blobs {
            self.entries_of(&b, None, &mut out)?;
        }
        for c in commits {
            for b in self.cx.engine.commit_blobs(&c)?.iter() {
                self.entries_of(b, None, &mut out)?;
            }
        }
        Ok(out)
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
    fn unfollow_facts(&mut self, s: &SyncId, c: &CommitId) {
        self.cx.engine.unfollow_facts(s, c);
    }
    fn unfollow_fate(&mut self, c: &CommitId) {
        self.cx.engine.unfollow_fate(c);
    }
    fn mintings(&mut self, t: &Tid) -> Arc<Vec<osis_engine::retention::Minting>> {
        Arc::new(self.cx.engine.mintings_of(t))
    }
    fn fall_mark(&mut self, _s: &SyncId, c: &CommitId) -> u64 {
        self.cx.engine.body_fall_mark(c)
    }
    fn credentials(&mut self, s: &SyncId) -> Result<Option<Arc<ReadCredentials>>> {
        Ok(self.cx.engine.read_credentials(s)?)
    }
    fn reads(&mut self, s: &SyncId) -> bool {
        self.cx.store.holding(s) == Some(osis_engine::sync::Holding::Read)
    }
    fn holdings_moved(&mut self) -> Vec<SyncId> {
        self.feeds.syncs.as_mut().map(|f| f.added()).unwrap_or_default()
    }
    fn unit_settled(&mut self, s: &SyncId) -> Result<bool> {
        let things = self.things(s);
        for t in &things {
            if !self.cx.engine.unit_settled(t)? {
                return Ok(false);
            }
        }
        Ok(!things.is_empty())
    }
    fn pullable(&mut self, s: &SyncId) -> Result<bool> {
        // a source of S up now (stamped: a source joining judges again)
        if self.views.any(s) {
            return Ok(true);
        }
        Ok(self.cx.engine.publishes_reach()?)
    }
    fn may_log(&mut self, s: &SyncId, c: &CommitId) -> Result<bool> {
        // S's own entries first, read by key: what may be logged only grows with the blobs
        // held, so where they do, no other sync ID's entries are read (a commit logged under
        // many sync IDs judges each without the others)
        let mut own = Vec::new();
        for b in self.cx.engine.commit_blobs(c)?.iter() {
            if self.cx.store.entry(s, b)?.is_some() && self.cx.store.blob_len(b)?.is_some() {
                own.push(*b);
            }
        }
        if !own.is_empty() && self.cx.engine.may_log(s, c, &own)? {
            return Ok(true);
        }
        let held: Vec<BlobId> = self.held_blobs(c)?.into_iter().map(|(b, _, _)| b).collect();
        Ok(self.cx.engine.may_log(s, c, &held)?)
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
    fn stands(&mut self, s: &SyncId, c: &CommitId, e: &Entry) -> Result<bool> {
        Ok(self.under_head(s, e)? || self.registers_step(s, c, e)?)
    }
    fn holds_body(&mut self, s: &SyncId, b: &BlobId) -> Result<bool> {
        Ok(self.cx.engine.holds_body(s, b)?)
    }
    fn promotion(&mut self, s: &SyncId, c: &CommitId, b: &BlobId) -> Result<crate::inbox::Promotion> {
        crate::inbox::promotion(self.cx.engine, self.cx.store, s, c, b)
    }
    fn restamp(&mut self, s: &SyncId, b: &BlobId) -> Result<()> {
        let Some(e) = self.cx.store.entry(s, b)? else { return Ok(()) };
        if stamp_key(self.cx, s)?.is_none() {
            return Ok(());
        }
        // a role commit a recorded step registers under the earliest such step's parent whose
        // write key is held (`registers_step`), anything else under the served head
        let mut w = None;
        if let Some(c) = self.cx.engine.blob_commit(b) {
            let creds = self.cx.engine.read_credentials(s)?;
            for p in self.step_parents(s, &c)? {
                w = w.or_else(|| creds.as_ref().and_then(|cr| cr.keys.get(&p.id())).and_then(|k| k.write.clone()));
            }
        }
        let Some(w) = w.or(stamp_key(self.cx, s)?) else { return Ok(()) };
        let stamp = osis_blob::sign_stamp(&w, s, b, &e.wrap, e.role);
        let own = e.own;
        self.cx.store.log(s, Entry { stamp: Some(stamp), deposited: false, own: true, ..e }, None, None)?;
        if !own {
            self.cx.store.uncharge(s, b)?;
        }
        Ok(())
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
    fn blob(&mut self, b: &BlobId) -> Result<Option<BlobInfo>> {
        if self.cx.store.blob_len(b)?.is_none() {
            return Ok(None);
        }
        let Some(x) = self.cx.engine.blob_of(b) else { return Ok(None) };
        Ok(Some(BlobInfo { parts: x.parts.clone(), sealed: x.sealed.clone(), copy: x.copy }))
    }
    fn dropped(&mut self, b: &BlobId) -> bool {
        self.cx.engine.blob_dropped(b)
    }
    fn strict_subset(&mut self, s: &SyncId, b: &BlobId, held: &BTreeSet<BlobId>) -> Result<bool> {
        Ok(self.cx.engine.strict_subset(s, b, held)?)
    }
    fn neither(&mut self, s: &SyncId, c: &CommitId, there: &BTreeSet<BlobId>) -> Result<bool> {
        Ok(self.cx.engine.neither(s, c, there)?)
    }
    fn sources(&mut self, s: &SyncId) -> Arc<Vec<SrcView>> {
        let mut out = Vec::new();
        for at in self.views.of(s) {
            out.extend(self.source(s, &at));
        }
        Arc::new(out)
    }
    fn reached(&mut self, s: &SyncId) -> Vec<(Source, ConnId)> {
        self.views.of(s).iter().filter_map(|at| self.views.get(s, at)).map(|v| (v.at, v.conn)).collect()
    }
    fn source(&mut self, s: &SyncId, at: &Source) -> Option<SrcView> {
        let mut v = self.views.get(s, at)?;
        let known = self.streams.known();
        v.head = known.head(*at, s);
        v.full = known.full(v.conn, s);
        Some(v)
    }
    fn holds(&mut self, c: &CommitId) -> bool {
        self.cx.engine.holds_commit(c)
    }
    fn kept_at(&mut self, s: &SyncId, at: &Source) -> bool {
        self.streams.known().kept(*at, s)
    }
    fn head_at(&mut self, s: &SyncId, at: &Source) -> Option<StepId> {
        self.streams.known().head(*at, s)
    }
    fn shown_at(&mut self, s: &SyncId, c: &CommitId) -> Result<BTreeSet<Source>> {
        let known = self.streams.known();
        Ok(self.cx.engine.commit_blobs(c)?.iter().flat_map(|b| known.shown_at(s, b)).collect())
    }
    fn sources_added(&mut self) -> Vec<(SyncId, Source)> {
        self.feeds.views.as_mut().map(|f| f.added()).unwrap_or_default().into_iter().map(|(_, s, at)| (s, at)).collect()
    }
    fn seen_added(&mut self) -> Result<Vec<(Source, SyncId, CommitId)>> {
        let mut out = Vec::new();
        let rows = match self.feeds.known.as_mut() {
            Some(f) => f.added(),
            // a start: every row each source showed, present or deleted
            None => {
                self.feeds.known = Some(self.streams.known().feed());
                let mut rows = self.streams.known().rows_all()?;
                rows.extend(self.cx.store.deletes_seen_all()?);
                rows
            }
        };
        // a blob this node never opened or sealed names no commit here: it is pulled, and its
        // commit known, once opened
        for (at, s, b) in rows {
            if let Some(c) = self.cx.engine.blob_commit(&b) {
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
    fn heard_out(&mut self, s: &SyncId) -> Result<bool> {
        self.status.heard_out_or_alone(self.opens, self.cx.engine, self.cx.store, s, &NetView { streams: self.streams, unread: self.unread })
    }
    fn stand(&mut self, at: &Source, s: &SyncId, c: &CommitId) -> Result<Option<Stand>> {
        self.cx.store.stand(*at, s, &c.0)
    }
    fn log_own(&mut self, s: &SyncId, c: &CommitId, fresh: bool) -> Result<Option<BlobId>> {
        let class = if self.cx.engine.sync_body(s, c)?.is_some() { Class::Durable } else { return Ok(None) };
        if !fresh {
            // a held blob of the commit not tombstoned under S, verbatim under a wrap for S
            for b in self.cx.engine.commit_blobs(c)?.iter() {
                if self.cx.store.tombstone(s, b)?.is_some() || self.cx.store.blob_len(b)?.is_none() || self.cx.engine.blob_dropped(b) {
                    continue;
                }
                for from in &self.homes_naming(b, c)? {
                    // a peer's deposit under S is stamped only as promoted (`Ground::promotion`)
                    let Some(e) = self.cx.store.entry(from, b)?.filter(|e| from != s || !e.deposited || e.own) else { continue };
                    let Some(wrap) = self.cx.engine.rewrap(c, b, from, &e.wrap, s)? else { continue };
                    let e = own_entry(self.cx, s, *b, wrap, e.class)?;
                    let code = self.cx.store.log(s, e, None, None)?;
                    return Ok((code == osis_proto::Code::OK).then_some(*b));
                }
            }
        }
        let Some((sealed, wrap)) = self.fresh(s, c)? else { return Ok(None) };
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
    fn fetch(&mut self, at: &SrcView, s: &SyncId, b: &BlobId) -> Result<()> {
        self.fetches.push((at.conn, *s, *b));
        Ok(())
    }
    fn delete_item(&mut self, s: &SyncId, head: &StepId, b: &BlobId) -> Result<Option<DeleteItem>> {
        let Some(keys) = self.cx.engine.read_credentials(s)?.and_then(|c| c.keys.get(head).cloned()) else { return Ok(None) };
        if keys.delete.is_some() {
            return Ok(delete_item(&keys, s, *b, true, None));
        }
        Ok(delete_item(&keys, s, *b, false, self.cx.engine.blob_delete_basis(b).as_ref()))
    }
    fn delete(&mut self, at: &SrcView, s: &SyncId, head: &StepId, b: &BlobId) -> Result<()> {
        let Some(item) = self.delete_item(s, head, b)? else { return Ok(()) };
        if let Some(session) = self.sessions.get_mut(at.conn) {
            session.request(To::Read, Msg::Delete { id: 0, sync_id: *s, items: vec![item] });
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
        if let Some(w) = write
            && e.stamp.is_some()
            && self.cx.store.stamp_under(s, b, &[w])?
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
    fn cert_blobs_missing(&mut self, s: &SyncId, r: CertKind) -> Result<CertBlobsMissing> {
        // nothing can be sealed under S yet (a rotation owed before encrypting): what is missing
        // is told once it can, so the effect acts then
        let missing = match (self.cx.engine.cert_wrap(s, r.as_ref())?, r) {
            (false, _) => BTreeSet::new(),
            (true, None) => (*self.cx.engine.certificate_records(s)?).clone(),
            (true, Some(r)) => (*self.cx.engine.certificate_lists(s, &r)?).clone(),
        };
        let mut out = CertBlobsMissing { missing, ..CertBlobsMissing::default() };
        for (b, tids) in self.cx.engine.cert_blobs(s, r).iter() {
            let Some(e) = self.cx.store.entry(s, b)?.filter(|e| e.own) else {
                out.gone.insert(*b);
                continue;
            };
            if !self.under_head(s, &e)? {
                out.stale.insert(*b);
            }
            out.missing.retain(|t| !tids.contains(t));
        }
        Ok(out)
    }
    fn list_rotations(&mut self, s: &SyncId) -> Result<Vec<CommitId>> {
        Ok(self.cx.engine.list_rotations(s)?)
    }
    fn lists_added(&mut self) -> Result<Vec<(SyncId, CommitId)>> {
        let added = match self.feeds.lists.as_mut() {
            Some(f) => f.added(),
            None => {
                // from the first call: the rows before are read with each S (`list_rotations`)
                self.feeds.lists = Some(self.cx.engine.lists_feed());
                Vec::new()
            }
        };
        let mut out = Vec::new();
        for (t, r) in added {
            if let osis_engine::sync::ThingSync::Read(ids) = self.cx.engine.thing_sync(&t)? {
                out.extend(ids.into_iter().map(|s| (s, r)));
            }
        }
        Ok(out)
    }
    fn forget_cert_blobs(&mut self, s: &SyncId, r: CertKind, gone: &BTreeSet<osis_base::BlobId>) -> Result<()> {
        for b in gone {
            self.cx.engine.forget_cert_blob(s, r, b)?;
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
    fn log_cert_blob(&mut self, s: &SyncId, r: CertKind, tids: &BTreeSet<osis_base::Tid>) -> Result<()> {
        let sealed = match r {
            None => self.cx.engine.seal_records(s, tids, self.cx.rng)?,
            Some(r) => self.cx.engine.seal_lists(s, &r, tids, self.cx.rng)?,
        };
        let Some((blob, bytes, wrap)) = sealed else { return Ok(()) };
        let e = own_entry(self.cx, s, blob, wrap, Class::Durable)?;
        self.cx.store.log(s, e, Some(bytes), None)?;
        Ok(())
    }
    fn piece_roots(&mut self, c: &CommitId, parts: &osis_engine::sync::PartSet) -> Result<Arc<Vec<PieceLink>>> {
        Ok(Arc::new(self.cx.engine.piece_roots(c, parts)?))
    }
    fn piece_below(&mut self, p: &PieceLink) -> Result<Option<Arc<Vec<PieceLink>>>> {
        Ok(self.cx.engine.piece_below(p)?)
    }
    fn piece(&mut self, s: &SyncId, b: &BlobId) -> Result<PieceAt> {
        // an own entry stamped under no head this node writes is logged again (stamped in place)
        Ok(match self.cx.store.entry(s, b)? {
            Some(e) if e.own && self.under_head(s, &e)? => PieceAt::Own,
            Some(_) => PieceAt::Peer,
            None if self.cx.store.tombstone(s, b)?.is_some() => PieceAt::Tombstoned,
            None => PieceAt::Absent,
        })
    }
    fn piece_shown(&mut self, at: &Source, s: &SyncId, b: &BlobId) -> bool {
        self.streams.known().knows(*at, s, b)
    }
    fn piece_deleted(&mut self, at: &Source, s: &SyncId, b: &BlobId) -> Result<bool> {
        self.cx.store.seen_deleted(*at, s, b)
    }
    fn log_piece(&mut self, s: &SyncId, b: &BlobId) -> Result<()> {
        if let Some(e) = self.cx.store.entry(s, b)? {
            // stamped in place where this node writes S's head, else a peer's entry of it (its
            // wrap and stamp as they came) becomes own
            if stamp_key(self.cx, s)?.is_some() {
                if !e.own || !self.under_head(s, &e)? {
                    self.restamp(s, b)?;
                }
            } else if !e.own {
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
    fn take(&mut self, s: &SyncId, b: &BlobId) -> Result<()> {
        let (Some(e), Some(bytes)) = (self.cx.store.entry(s, b)?, self.cx.store.bytes(b)?) else { return Ok(()) };
        crate::store::open_entry(self.cx.engine, self.cx.store, s, b, &e.wrap, &bytes)?;
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
    fn freed_added(&mut self) -> Vec<(BlobId, Tid)> {
        match self.feeds.freed.as_mut() {
            Some(f) => f.added(),
            None => {
                self.feeds.freed = Some(self.cx.engine.freed_feed());
                self.cx.engine.freed_rows()
            }
        }
    }
    fn freed_link(&mut self, b: &BlobId, t: &Tid) -> bool {
        self.cx.engine.freed_link(b, t).is_some()
    }
    fn carrying(&mut self, t: &Tid) -> Result<BTreeSet<SyncId>> {
        Ok(self.cx.engine.carrying(t)?)
    }
    fn drop_blob(&mut self, s: &SyncId, b: &BlobId) -> Result<()> {
        self.cx.store.drop_entry(s, b, Vec::new())?;
        Ok(())
    }
    fn delete_freed(&mut self, at: &SrcView, s: &SyncId, head: &StepId, b: &BlobId, t: &Tid) -> Result<()> {
        let Some(f) = self.cx.engine.freed_link(b, t) else { return Ok(()) };
        let Some(keys) = self.cx.engine.read_credentials(s)?.and_then(|c| c.keys.get(head).cloned()) else { return Ok(()) };
        let Some(item) = delete_item(&keys, s, f.link.blob, f.borne, self.cx.engine.freed_delete_basis(&f).as_ref()) else { return Ok(()) };
        if let Some(session) = self.sessions.get_mut(at.conn) {
            session.request(To::Read, Msg::Delete { id: 0, sync_id: *s, items: vec![item] });
        }
        Ok(())
    }
    fn freed_done(&mut self, b: &BlobId, t: &Tid) -> Result<()> {
        Ok(self.cx.engine.freed_done(&[(*t, *b)])?)
    }
    fn forgettable(&mut self, c: &CommitId) -> Result<Option<bool>> {
        Ok(self.cx.engine.held_fate(c)?.map(|f| f.forgettable))
    }
    fn known_under(&mut self, c: &CommitId) -> Result<BTreeSet<SyncId>> {
        let mut out = BTreeSet::new();
        for b in self.cx.engine.commit_blobs(c)?.iter() {
            out.extend(self.cx.store.naming(b)?);
            out.extend(self.cx.store.tombstoned_under(b)?);
        }
        Ok(out)
    }
    fn covered_drops(&mut self, c: &CommitId) -> Result<Vec<(Tid, osis_base::Ak)>> {
        Ok(self.cx.engine.held_fate(c)?.map(|f| f.drops.to_vec()).unwrap_or_default())
    }
    fn drop_body(&mut self, c: &CommitId, t: &Tid, ak: &osis_base::Ak) -> Result<()> {
        Ok(self.cx.engine.drop_body(c, t, ak)?)
    }
    fn forget_commits(&mut self, cs: &[CommitId]) -> Result<()> {
        Ok(self.cx.engine.forget_commits(cs)?)
    }
}

/// A Delete of blob `b` at a source on head keys `keys` (spec/sync-ids.md §6 Delete): by the
/// head's delete key where held and `by_key` (it deletes every entry there), else by levels over
/// `basis` with the role key they need (`osis_blob::cover_levels`; the sync key only of an
/// established epoch). One rule for every blob a node deletes at a source keeping S unread:
/// commit blobs and freed links alike.
fn delete_item(keys: &osis_engine::sync_ids::HeadKeys, s: &SyncId, b: BlobId, by_key: bool, basis: Option<&osis_engine::sync::DeleteBasis>) -> Option<DeleteItem> {
    if by_key && let Some(d) = &keys.delete {
        return Some(DeleteItem::sign(d, s, b));
    }
    let basis = basis?;
    let role = |r: osis_crypto::RoleKey| match r {
        osis_crypto::RoleKey::Write => keys.write.clone(),
        osis_crypto::RoleKey::Sync if keys.sync_established => keys.sync.clone(),
        _ => None,
    };
    let dks = osis_blob::cover_levels(&basis.prefix, &basis.blind, &basis.held, |r| role(r).is_some())?;
    let levels: Vec<osis_blob::Level> = dks.iter().map(|x| x.0).collect();
    let key = role(osis_blob::key_for_levels(&levels).ok()?)?;
    DeleteItem::sign_by(&key, &dks, basis.prefix.salt(), &basis.blind, s, b).ok()
}
