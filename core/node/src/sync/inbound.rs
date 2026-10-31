//! What arrives (spec/sync.md §3, §6, §8, §9): log events and fetched entries become label
//! entries; blob bytes go to the store; commit blobs are unwrapped with the group's read secrets
//! (newest first), checked against their prefix and ingested, membership commits first; inbox
//! blobs are opened with the read KEM key of the actor whose inbox the label is; entries that
//! open with nothing held are retried when new secrets arrive; pages of waiting commits are
//! fetched before apply; ephemeral entries go to the ephemeral lane (`ephemeral`).

use super::state::{BlobRec, Entry, Hint, Kind, ServerKey};
use super::{ConnId, Phase, RELINK_BACKOFF_MAX_MS, RELINK_BACKOFF_MS, SyncEngine};
use crate::error::Result;
use crate::labeling::open_commit;
use crate::Ingested;
use osis_base::{BlobId, Classified, CommitId, ErrorClass, LabelId, Tid};
use osis_crypto::{Secret32, VerifyingKey, role_kem};
use osis_label::Step;
use osis_proto::{Code, Command, Cursor, Event as LogEvent};
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};

/// An opened inbox blob: its prefix expiry (none: never), the aspect indexes its commit
/// carries, the things its payload names, and its commit's author, actor and signature (an
/// invite request is judged and shown by them).
#[derive(Clone, Debug)]
pub(crate) struct Opened {
    pub until: u64,
    pub ais: BTreeSet<usize>,
    pub things: Vec<osis_label::InboxThing>,
    pub author: Tid,
    pub actor: Tid,
    pub signature: osis_crypto::Signature,
    /// The first thing the commit writes an edge on (`/members`), else the first it names.
    pub target: Option<Tid>,
}

impl Opened {
    fn new(prefix: &osis_label::Prefix, c: &osis_commit::CommitBlob, things: Vec<osis_label::InboxThing>) -> Opened {
        let h = &c.header;
        let target = h.aspects.iter().find(|a| a.ak.as_str() == "/members").map(|a| a.tid).or_else(|| things.first().map(|t| t.tid));
        Opened { until: prefix.expiry().map_or(u64::MAX, |w| w.0), ais: c.parts.iter().map(|p| p.ai).collect(), things, author: h.author, actor: h.actor, signature: c.signature, target }
    }
}

/// An invite request (spec/sync.md §3): an inbox blob's commit held back until the user
/// accepts. `actor` and `target` are the sender's word.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteRequest {
    pub commit: CommitId,
    pub actor: Tid,
    pub target: Option<Tid>,
}

/// Rounds of "new secrets opened more entries" per batch.
const MAX_ROUNDS: usize = 16;

impl SyncEngine {
    /// The group a label belongs to, as an open connection or the recorded labels know it.
    pub(crate) fn group_of(&mut self, l: &LabelId) -> Option<Tid> {
        for c in self.conns.values() {
            if let Some(x) = c.labels.get(l) {
                return Some(x.group);
            }
        }
        if let Some(h) = self.state.hints.get(l) {
            return Some(h.thing);
        }
        self.labels().into_iter().find(|(_, gl)| gl.id == *l).map(|(g, _)| g)
    }

    /// Re-encrypts the deleted chunks waiting in `relink_pending` (`Engine::relink`), at most
    /// once per back-off interval per aspect; those an aspect's back-off holds back wait until it
    /// passes (retried on ticks), the rest are done.
    pub(crate) fn relink_lost(&mut self) -> Result<()> {
        let now = self.now();
        if self.relink_pending.is_empty() || now < self.relink_at {
            return Ok(());
        }
        let backoff = &mut self.relink_backoff;
        let mut next: Option<u64> = None;
        let mut allow = |t: &Tid, ak: &osis_base::Ak| {
            let e = backoff.entry((*t, ak.clone())).or_insert((0, RELINK_BACKOFF_MS));
            if now < e.0 {
                next = Some(next.map_or(e.0, |n| n.min(e.0)));
                return false;
            }
            *e = (now.saturating_add(e.1), e.1.saturating_mul(2).min(RELINK_BACKOFF_MAX_MS));
            true
        };
        let pending = self.relink_pending.clone();
        let r = self.engine.relink(&pending, &mut allow);
        match next {
            Some(n) => self.relink_at = n,
            None => self.relink_pending.clear(),
        }
        match r {
            Err(e @ crate::Error::Store(_)) => Err(e),
            Err(e) => {
                self.relink_pending.clear();
                self.diag(format!("re-encrypting deleted chunks: {e}"));
                Ok(())
            }
            Ok(_) => Ok(()),
        }
    }

    /// Log events of a Sync reply, a push, a fetch or a bundle (`conn` none).
    pub(crate) fn log_events(&mut self, conn: Option<ConnId>, l: LabelId, events: Vec<LogEvent>, cursor: Option<Cursor>, out: &mut Vec<super::Action>) -> Result<()> {
        self.log_events_from(conn, None, l, events, cursor, out)
    }

    /// `log_events`, of entries a session this node serves (`served`) uploaded.
    pub(crate) fn log_events_from(&mut self, conn: Option<ConnId>, served: Option<ConnId>, l: LabelId, events: Vec<LogEvent>, cursor: Option<Cursor>, out: &mut Vec<super::Action>) -> Result<()> {
        let from = match served {
            Some(c) => super::ephemeral::RelayFrom::Served(c),
            None => super::ephemeral::RelayFrom::Server(conn.and_then(|c| self.conns.get(&c)).map(|c| c.server)),
        };
        let server: Option<ServerKey> = conn.and_then(|c| self.conns.get(&c)).map(|c| c.server);
        let mut blobs = Vec::new();
        let mut touched = Vec::new();
        let mut fetch = Vec::new();
        // entries new here that no writer vouched for (a deposit, or a server's junk): no stamp
        // under the head's write key, or before a head is known any step's this node knows (a
        // server cannot make one; a superseded step's key may be a removed writer's)
        let mut unvouched = Vec::new();
        // the head's write key now (a Head event in the batch moves it)
        let head_write = |s: &Self| conn.and_then(|c| s.lc(c, &l)).and_then(|x| x.head.as_ref()).map(|h| h.keys.write);
        let first_write = head_write(self);
        let mut writers: Vec<VerifyingKey> = Vec::new();
        if first_write.is_none() && server.is_some() && events.iter().any(|e| matches!(e, LogEvent::Added { .. })) {
            writers = conn.and_then(|c| self.lc(c, &l)).map(|x| x.writers.clone()).unwrap_or_default();
            if let Some(g) = self.group_of(&l)
                && let Some(gl) = self.group_label(&g, &l)
            {
                for (st, _) in gl.steps.values() {
                    if !writers.contains(&st.keys.write) {
                        writers.push(st.keys.write);
                    }
                }
            }
        }
        // deleted blobs that are no commit blob: chunks a live value may still link
        let mut lost = BTreeSet::new();
        for ev in events {
            // an ephemeral or relay-only entry is held in memory only (`ephemeral`)
            let ev = match ev {
                LogEvent::Added { blob_id, blob: Some(blob), wrap, stamp } if osis_label::Prefix::parse(&blob).is_ok_and(|p| p.class() != osis_label::Class::Durable) => {
                    let class = osis_label::Prefix::parse(&blob).map(|p| p.class()).unwrap_or_default();
                    let head = conn.and_then(|c| self.lc(c, &l)).and_then(|x| x.head.as_ref()).map(|h| h.keys.write);
                    // a stamp counts if it verifies under the head's write key (a served peer's
                    // upload was checked by the server engine)
                    let stamp = stamp.filter(|s| head.as_ref().map_or(conn.is_none(), |w| osis_label::verify_stamp(w, &l, &blob_id, &wrap, s).is_ok()));
                    if let Some(c) = conn.and_then(|c| self.conns.get_mut(&c)) {
                        c.req.missing.remove(&blob_id);
                        c.req.fetching.remove(&blob_id);
                    }
                    self.eph_added(from, l, blob_id, blob, wrap, stamp, class, out)?;
                    continue;
                }
                // one that never fits here is not fetched again (`Unfit`)
                LogEvent::Added { blob_id, blob: None, .. } if self.eph.unfit.contains(l, blob_id) => continue,
                LogEvent::Added { blob_id, blob: None, .. } if self.eph.entries.contains_key(&(l, blob_id)) => {
                    if let Some(s) = server {
                        self.eph.present.insert((s, l, blob_id));
                    }
                    continue;
                }
                LogEvent::Deleted(b) if self.eph_deleted(server, l, b) => continue,
                ev => ev,
            };
            match ev {
                LogEvent::Added { blob_id, blob, wrap, stamp } => {
                    let signed_by = |w: &VerifyingKey| stamp.is_some_and(|st| osis_label::verify_stamp(w, &l, &blob_id, &wrap, &st).is_ok());
                    let cur = head_write(self);
                    let by_head = cur.as_ref().is_some_and(signed_by);
                    let vouched = match &first_write {
                        Some(w) if cur.as_ref() == Some(w) => by_head,
                        Some(w) => signed_by(w),
                        None => writers.iter().any(signed_by),
                    };
                    if let Some(s) = server {
                        self.state.set_present(s, l, blob_id, true);
                        self.state.set_deposited(s, l, blob_id, stamp.is_none());
                    }
                    // the server holds it now: fetched there again when wanted
                    if let Some(c) = conn.and_then(|c| self.conns.get_mut(&c)) {
                        c.req.missing.remove(&blob_id);
                    }
                    // a stamp counts only if it verifies under the head's write key (it is relayed);
                    // a bundle's stamps were checked against its path by the importer
                    let stamp = stamp.filter(|_| if cur.is_some() { by_head } else { conn.is_none() });
                    match self.state.entries.get(&(l, blob_id)).cloned() {
                        None => {
                            if server.is_some() && stamp.is_none() && !vouched {
                                // bytes held before (another label's entry) stay whatever happens
                                let fresh = blob.is_some() && !self.engine.has_blob(&blob_id);
                                unvouched.push((blob_id, fresh));
                            }
                            self.state.set_entry(l, blob_id, Entry { wrap, stamp, cert: false, kind: Kind::Unknown })
                        }
                        Some(mut e) if e.wrap != wrap || (stamp.is_some() && e.stamp != stamp) => {
                            // another wrap only if it opens to the blob key this node knows
                            let known = self.state.blobs.get(&blob_id).map(|r| r.key.clone());
                            let ok = match known {
                                None => true,
                                Some(k) => {
                                    let g = self.group_of(&l);
                                    let secrets = g.map(|g| self.read_secrets(&g)).unwrap_or_default();
                                    osis_label::unwrap_any(secrets.iter(), &blob_id, &wrap).is_some_and(|(_, x)| x.expose() == k.expose())
                                }
                            };
                            if ok {
                                e.wrap = wrap;
                                if stamp.is_some() {
                                    e.stamp = stamp;
                                }
                                self.state.set_entry(l, blob_id, e);
                            }
                        }
                        Some(_) => {}
                    }
                    match blob {
                        Some(b) => {
                            self.fetched(&blob_id);
                            blobs.push((blob_id, b));
                        }
                        None if !self.engine.has_blob(&blob_id) => fetch.push(blob_id),
                        None => {}
                    }
                    touched.push(blob_id);
                }
                LogEvent::Deleted(b) => {
                    // gone from every server of the label: a chunk an own commit may link
                    let chunk = !self.state.blobs.contains_key(&b);
                    if self.absent_at(server, l, b)? && chunk {
                        lost.insert(b);
                    }
                }
                LogEvent::Pending { .. } => {}
                LogEvent::Head(step) => {
                    if let Some(c) = conn {
                        self.new_head(c, l, step, out)?;
                    }
                }
            }
        }
        // a chunk a live value here links, deleted by a purger that had not seen its reuse:
        // written again re-encrypted, one commit for the batch (spec/sync.md §1); not one a
        // replaced label lost (its content goes, the replacement holds it)
        let replaced = self.group_of(&l).is_some_and(|g| self.is_replaced(&g, &l));
        if !lost.is_empty() && !replaced {
            self.relink_pending.extend(lost);
            self.relink_at = 0;
            self.relink_lost()?;
        }
        if let (Some(s), Some(c)) = (server, cursor) {
            self.state.set_cursor(s, l, Some(c));
        }
        // a push (no Sync running) brings the log to its end: a pass end
        let pushed = conn.and_then(|c| self.conns.get(&c)).and_then(|c| c.labels.get(&l)).is_some_and(|x| x.synced && !x.syncing);
        // the label changed under us: a pass decides again (carriers, retags)
        if !touched.is_empty()
            && let Some(lc) = conn.and_then(|c| self.conns.get_mut(&c)).and_then(|c| c.labels.get_mut(&l))
        {
            lc.dirty = true;
        }
        // bodies waiting for a linked blob upload it now it is here (`Left::links`)
        self.touched.blobs.extend(blobs.iter().map(|(b, _)| *b));
        self.engine.put_blobs(blobs)?;
        self.open_entries(l, &touched)?;
        if let Some(s) = server {
            self.drop_unvouched(s, l, &unvouched)?;
        }
        // commit blobs announced without bytes are fetched now; the rest (chunks) lazily
        if let Some(c) = conn {
            let g = self.group_of(&l);
            let secrets = g.map(|g| self.read_secrets(&g)).unwrap_or_default();
            let want: Vec<BlobId> = fetch.into_iter().filter(|b| self.state.entries.get(&(l, *b)).is_some_and(|e| osis_label::unwrap_any(secrets.iter(), b, &e.wrap).is_some())).collect();
            self.fetch_on(c, l, want, out)?;
            self.fetch_waiting(c, l, out)?;
        }
        if pushed && let Some(s) = server {
            self.bump_pass(s, l)?;
        }
        Ok(())
    }

    /// New entries no writer vouched for that neither opened nor unwrap under a held read secret
    /// (a deposit under an epoch not held yet, an entry stamped under a step this node does not
    /// know, or a server's junk): their bytes are not kept (fetched again once they unwrap,
    /// `refetch`), and beyond `SyncConfig::unvouched_cap` such entries under the label at that
    /// server not even its presence there, nor the entry once no server has it
    /// (spec/requirements.md: peer input never causes unbounded storage; a dropped real entry
    /// comes back stamped once a writer promotes it, or with the next replay). Counted per server:
    /// one server's junk does not crowd out what others announce.
    fn drop_unvouched(&mut self, server: ServerKey, l: LabelId, ids: &[(BlobId, bool)]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let secrets = self.group_of(&l).map(|g| self.read_secrets(&g)).unwrap_or_default();
        // pages and chunks a waiting commit lists (a reader's deposited commit) stay
        let mut listed = BTreeSet::new();
        for (c, r) in self.engine.pending() {
            if r == crate::Reason::WaitBlobs
                && let Some(h) = self.engine.commit_bytes(&c)?.and_then(|b| osis_commit::CommitBlob::decode(&b).ok()).map(|cb| cb.header)
            {
                listed.extend(h.chunks.iter().map(|ch| ch.blob));
            }
        }
        // an inbox blob opens by its bytes (the read KEM key of an epoch learned later): kept,
        // under a smaller cap
        let inbox = !self.inbox_of(&l).is_empty();
        let cap = if inbox { self.cfg.unvouched_cap >> 4 } else { self.cfg.unvouched_cap };
        let mut held = self.state.present_at(&server, &l).into_iter().filter(|b| self.state.entries.get(&(l, *b)).is_some_and(|e| e.kind == Kind::Unknown && e.stamp.is_none())).count();
        let mut gone = Vec::new();
        let mut over = 0usize;
        for (b, fresh) in ids {
            let unopened = !listed.contains(b) && self.state.entries.get(&(l, *b)).is_some_and(|e| e.kind == Kind::Unknown && e.stamp.is_none() && osis_label::unwrap_any(secrets.iter(), b, &e.wrap).is_none());
            if !unopened {
                continue;
            }
            let drop = held > cap;
            if *fresh && !self.state.blobs.contains_key(b) && (drop || !inbox) {
                gone.push(*b);
            }
            if drop {
                self.state.set_present(server, l, *b, false);
                if !self.state.present_anywhere(&l, b) {
                    self.state.drop_entry(l, *b);
                    self.fetched(b);
                }
                held -= 1;
                over += 1;
            }
        }
        if over > 0 {
            self.diag(format!("label {l:?}: {over} unopened unstamped entries over the cap dropped"));
        }
        self.delete_blobs(&gone)
    }

    /// Deletes the bytes of blobs `ids` from the store.
    pub(crate) fn delete_blobs(&mut self, ids: &[BlobId]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        self.engine.run(|tx| {
            for b in ids {
                tx.txn.delete_blob(b);
            }
            Ok(())
        })
    }

    /// Held read secrets of a group (`Engine::read_secrets`).
    pub(crate) fn read_secrets(&self, g: &Tid) -> Vec<Secret32> {
        self.engine.read_secrets(g)
    }

    /// Actors whose inbox is `l`.
    pub(crate) fn inbox_actors(&mut self, l: &LabelId) -> Vec<Tid> {
        self.inbox_of(l).into_iter().map(|(a, _)| a).collect()
    }

    /// Actors whose inbox is `l`, with their held read KEM secrets.
    fn inbox_of(&mut self, l: &LabelId) -> Vec<(Tid, Vec<Secret32>)> {
        let actors: Vec<Tid> = self.engine.core.ix.secrets.keys().copied().collect();
        let mut out = Vec::new();
        for a in actors {
            let inbox = self.engine.get_typed(&a, &ct::KEYS).ok().flatten().and_then(|k| k.inbox);
            if inbox.is_some_and(|i| i.label == *l) {
                out.push((a, self.read_secrets(&a)));
            }
        }
        out
    }

    /// Opens entries of `l` not opened yet, ingests what they carry (membership first), and
    /// retries every unopened entry while new secrets keep arriving.
    pub(crate) fn open_entries(&mut self, l: LabelId, ids: &[BlobId]) -> Result<()> {
        let mut todo: Vec<(LabelId, BlobId)> = ids.iter().map(|b| (l, *b)).collect();
        for _ in 0..MAX_ROUNDS {
            let before = self.secrets_count();
            let mut commits: Vec<(Vec<u8>, osis_commit::CommitBlob)> = Vec::new();
            for (l, b) in std::mem::take(&mut todo) {
                self.open_one(l, b, &mut commits)?;
            }
            commits.sort_by_key(|(_, c)| (!c.header.kind.is_membership(), c.header.ts));
            for (pt, c) in commits {
                if let Err(e) = self.engine.ingest(&pt, Vec::new()) {
                    self.diag(format!("ingest {:?}: {e}", c.id()));
                }
            }
            if self.secrets_count() == before {
                break;
            }
            todo = self.state.entries.iter().filter(|(_, e)| e.kind == Kind::Unknown).map(|(k, _)| *k).collect();
        }
        self.engine.reexamine()?;
        self.vet_inbox_hints()
    }

    fn secrets_count(&self) -> usize {
        self.engine.core.ix.secrets.values().map(|e| e.read.held_newest_first().len() + e.write.held_newest_first().len() + e.admin.held_newest_first().len()).sum()
    }

    fn open_one(&mut self, l: LabelId, b: BlobId, commits: &mut Vec<(Vec<u8>, osis_commit::CommitBlob)>) -> Result<()> {
        let Some(mut e) = self.state.entries.get(&(l, b)).cloned() else { return Ok(()) };
        if e.kind != Kind::Unknown {
            return Ok(());
        }
        let Some(bytes) = self.engine.blob(&b)? else { return Ok(()) };
        let Some(g) = self.group_of(&l) else { return Ok(()) };
        let secrets = self.read_secrets(&g);
        if let Some((_, key)) = osis_label::unwrap_any(secrets.iter(), &b, &e.wrap) {
            match open_commit(&bytes, &key) {
                Ok((pt, c)) => {
                    let parts: Vec<(usize, usize)> = c.parts.iter().map(|p| (p.ai, p.di)).collect();
                    let commit = c.id();
                    if !self.state.blobs.contains_key(&b) {
                        self.state.add_blob(b, BlobRec { commit, parts: parts.clone(), key, cert: e.cert });
                    }
                    let salt = osis_label::Prefix::parse(&bytes).map(|p| *p.salt()).unwrap_or_default();
                    e.kind = Kind::Commit { commit, parts, salt };
                    self.state.set_entry(l, b, e);
                    commits.push((pt, c));
                }
                Err(err) => {
                    // a commit this build cannot interpret is parked, anything else is bad
                    // input; neither is opened again (spec/versioning.md §2)
                    let pt = (err.class() == ErrorClass::Parked).then(|| osis_label::open(&bytes, &key).ok()).flatten();
                    e.kind = match pt.map(|(_, pt)| self.engine.ingest(&pt, Vec::new())) {
                        Some(Ok(Ingested::Parked(c))) => Kind::Parked(c),
                        Some(Err(x)) if x.class() == ErrorClass::Local => return Err(x),
                        _ => {
                            self.diag(format!("blob {b:?}: {err}"));
                            Kind::Bad
                        }
                    };
                    self.state.set_entry(l, b, e);
                }
            }
            return Ok(());
        }
        let Some((prefix, payload)) = self.open_inbox(&l, &bytes) else { return Ok(()) };
        let pt = osis_base::encode(&payload.commit);
        let c = osis_commit::CommitBlob::decode(&pt).ok();
        let o = c.as_ref().map(|c| Opened::new(&prefix, c, payload.things.clone()));
        // its labels are followed only once vetted (`vet_inbox_hints`)
        self.inbox_opened.insert((l, b), o.clone());
        let (Some(c), Some(o)) = (c, o) else {
            e.kind = Kind::Inbox(None);
            self.state.set_entry(l, b, e);
            return Ok(());
        };
        let id = c.id();
        if self.state.declined.contains(&id) {
            e.kind = Kind::Inbox(Some(id));
        } else if !self.admits(&id, &o, &mut None) {
            e.kind = Kind::Request(id);
        } else {
            self.engine.note_delete_hints(id, &payload.things)?;
            e.kind = Kind::Inbox(Some(id));
            commits.push((pt, c));
        }
        self.state.set_entry(l, b, e);
        Ok(())
    }

    /// Whether an opened inbox blob carrying commit `c` is admitted (spec/sync.md §3, invite
    /// requests): `c` is held (from a label this node syncs: a sibling device accepted it and
    /// placed its copy), or its sender is connected. `roots` caches what a sender must be named
    /// under within one judging round.
    fn admits(&mut self, c: &CommitId, o: &Opened, roots: &mut Option<BTreeSet<Tid>>) -> bool {
        if self.engine.core.ix.commits.contains_key(c) || self.engine.core.ix.pending.contains_key(c) {
            return true;
        }
        // the author's node, then the actors it is named on as a member, transitively
        let held = &self.engine.core.ix.held;
        let mut up = BTreeSet::new();
        let mut stack = vec![o.author];
        while let Some(t) = stack.pop() {
            if up.insert(t) {
                stack.extend(held.named_on(&t).copied());
            }
        }
        let roots = match roots {
            Some(r) => r,
            None => {
                let mut r = self.state.contacts.clone();
                for (g, _) in self.labels() {
                    r.extend(self.engine.owner_chain(&g));
                }
                roots.insert(r)
            }
        };
        if up.is_disjoint(roots) {
            return false;
        }
        // a connected author's signature: a stranger may name any node as the author
        match self.engine.core.created(&o.author) {
            Some(osis_base::CreationRecord::KeyActor { public_key, .. }) => VerifyingKey::from_slice(public_key).is_ok_and(|vk| osis_commit::verify_signature(c, &o.signature, &vk).is_ok()),
            _ => false,
        }
    }

    /// The request entries under the synced labels: (label, blob, commit).
    fn request_entries(&mut self) -> Vec<(LabelId, BlobId, CommitId)> {
        let labels: BTreeSet<LabelId> = self.labels().iter().map(|(_, x)| x.id).collect();
        labels
            .iter()
            .flat_map(|l| self.state.of_kind(l, 5).into_iter().map(move |b| (*l, b)))
            .filter_map(|(l, b)| match self.state.entries.get(&(l, b)).map(|e| &e.kind) {
                Some(Kind::Request(c)) => Some((l, b, *c)),
                _ => None,
            })
            .collect()
    }

    /// The invite requests waiting for the user (spec/sync.md §3), one per commit, unexpired.
    pub fn invite_requests(&mut self) -> Result<Vec<InviteRequest>> {
        let now = self.now();
        let mut out: BTreeMap<CommitId, InviteRequest> = BTreeMap::new();
        for (l, b, c) in self.request_entries() {
            let Some(o) = self.inbox_opened(&l, &b)? else { continue };
            if o.until > now {
                out.entry(c).or_insert(InviteRequest { commit: c, actor: o.actor, target: o.target });
            }
        }
        Ok(out.into_values().collect())
    }

    /// Admits the request entries of commit `c` (or of every admitted commit when `c` is none):
    /// ingests the commit and lets `vet_inbox_hints` follow what it names. Whether any was.
    fn release_requests(&mut self, c: Option<CommitId>) -> Result<bool> {
        let mut released = false;
        let mut roots = None;
        for (l, b, x) in self.request_entries() {
            if c.is_some_and(|c| c != x) {
                continue;
            }
            if c.is_none() {
                let Some(o) = self.inbox_opened(&l, &b)? else { continue };
                if !self.admits(&x, &o, &mut roots) {
                    continue;
                }
            }
            let Some(bytes) = self.engine.blob(&b)? else { continue };
            let Some((_, payload)) = self.open_inbox(&l, &bytes) else { continue };
            let pt = osis_base::encode(&payload.commit);
            let Ok(blob) = osis_commit::CommitBlob::decode(&pt) else { continue };
            if let Some(mut e) = self.state.entries.get(&(l, b)).cloned() {
                e.kind = Kind::Inbox(Some(x));
                self.state.set_entry(l, b, e);
            }
            self.engine.note_delete_hints(x, &payload.things)?;
            if let Err(e) = self.engine.ingest(&pt, Vec::new()) {
                self.diag(format!("ingest {:?}: {e}", blob.id()));
            }
            released = true;
        }
        Ok(released)
    }

    /// Accepts invite request `c` (spec/sync.md §3): its commit applies and what it names is
    /// followed. Whether a request of `c` was waiting.
    pub fn accept_invite(&mut self, c: CommitId) -> Result<(bool, Vec<super::Action>)> {
        if !self.release_requests(Some(c))? {
            return Ok((false, Vec::new()));
        }
        self.engine.reexamine()?;
        self.vet_inbox_hints()?;
        self.state.flush(&mut self.engine)?;
        Ok((true, self.handle(super::Event::Local)))
    }

    /// Declines invite request `c` (spec/sync.md §3): its commit stays unapplied for good, in
    /// every blob carrying it. Whether a request of `c` was waiting.
    pub fn decline_invite(&mut self, c: CommitId) -> Result<bool> {
        let mut found = false;
        for (l, b, x) in self.request_entries() {
            if x == c
                && let Some(mut e) = self.state.entries.get(&(l, b)).cloned()
            {
                e.kind = Kind::Inbox(Some(c));
                self.state.set_entry(l, b, e);
                found = true;
            }
        }
        if found {
            self.state.decline(c);
            self.state.flush(&mut self.engine)?;
        }
        Ok(found)
    }

    /// Opens inbox blob `bytes` under the held keys of an actor whose inbox `l` is.
    fn open_inbox(&mut self, l: &LabelId, bytes: &[u8]) -> Option<(osis_label::Prefix, osis_label::InboxPayload)> {
        self.inbox_of(l).into_iter().flat_map(|(a, keys)| keys.into_iter().map(move |s| (a, s))).find_map(|(a, s)| osis_label::open_inbox_blob(bytes, &a, &role_kem(&s)).ok())
    }

    /// What opened inbox blob `b` under `l` carries (cached; it opens again under the held keys
    /// of an actor whose inbox `l` is), if its bytes are held and its commit decodes.
    pub(crate) fn inbox_opened(&mut self, l: &LabelId, b: &BlobId) -> Result<Option<Opened>> {
        if let Some(x) = self.inbox_opened.get(&(*l, *b)) {
            return Ok(x.clone());
        }
        let Some(bytes) = self.engine.blob(b)? else { return Ok(None) };
        // one that no longer opens is not tried again (a KEM per try)
        let Some((prefix, payload)) = self.open_inbox(l, &bytes) else {
            self.inbox_opened.insert((*l, *b), None);
            return Ok(None);
        };
        let x = osis_commit::CommitBlob::decode(&osis_base::encode(&payload.commit)).ok().map(|c| Opened::new(&prefix, &c, payload.things));
        self.inbox_opened.insert((*l, *b), x.clone());
        Ok(x)
    }

    /// The aspect indexes of the commit inbox blob `b` under `l` carries and the things it
    /// names, if its bytes are held.
    pub(crate) fn inbox_parts(&mut self, l: &LabelId, b: &BlobId) -> Result<Option<(BTreeSet<usize>, Vec<Tid>)>> {
        Ok(self.inbox_opened(l, b)?.map(|o| (o.ais, o.things.iter().map(|t| t.tid).collect())))
    }

    /// Follows the labels opened inbox blobs name (spec/sync.md §3) as hints, from scratch: per
    /// unexpired blob whose commit is applied or pending, the first payload thing with no known
    /// label that the commit gave this node a read secret of (`Engine::boxed_by`), one per blob
    /// (a delivery names one thing), so the hints a sender makes are bounded by the inbox's
    /// deposit budget and go with the blob. The payload is the sender's word: servers only, never
    /// a node to dial (`peer://`); a label a key actor's entry is followed for (`via`) is left
    /// to that follow. Other inbox hints are dropped.
    pub(crate) fn vet_inbox_hints(&mut self) -> Result<()> {
        // requests admitted since (the sender became connected, a sibling device accepted)
        if self.release_requests(None)? {
            self.engine.reexamine()?;
        }
        let now = self.now();
        // the synced labels' inbox entries (runs per `run_dirty`: never a scan of every entry)
        let labels: BTreeSet<LabelId> = self.labels().iter().map(|(_, x)| x.id).collect();
        let inbox: Vec<(LabelId, BlobId, Option<CommitId>)> = labels
            .iter()
            .flat_map(|l| self.state.of_kind(l, 2).into_iter().map(move |b| (*l, b)))
            .filter_map(|(l, b)| match self.state.entries.get(&(l, b)).map(|e| &e.kind) {
                Some(Kind::Inbox(c)) => Some((l, b, *c)),
                _ => None,
            })
            .collect();
        let live: BTreeSet<(LabelId, BlobId)> = inbox.iter().map(|(l, b, _)| (*l, *b)).collect();
        self.inbox_opened.retain(|k, _| live.contains(k));
        let mut want: BTreeMap<LabelId, Hint> = BTreeMap::new();
        for (l, b, c) in inbox {
            let Some(c) = c else { continue };
            if !self.engine.core.ix.commits.contains_key(&c) && !self.engine.core.ix.pending.contains_key(&c) {
                continue;
            }
            let Some(o) = self.inbox_opened(&l, &b)? else { continue };
            if o.until <= now {
                continue;
            }
            for t in &o.things {
                if !self.engine.labels_of(&t.tid).is_empty() || !self.engine.boxed_by(&c, &t.tid) {
                    continue;
                }
                let servers = t.servers.iter().filter(|a| !super::peers::is_peer(a)).cloned();
                let src = super::state::InboxSource { label: l, blob: b, until: o.until };
                match want.get_mut(&t.label) {
                    // two blobs naming one label: both servers, the later expiry
                    Some(h) if h.thing == t.tid && h.index == t.index => {
                        for a in servers {
                            if !h.servers.contains(&a) {
                                h.servers.push(a);
                            }
                        }
                        if h.inbox.is_some_and(|i| i.until < o.until) {
                            h.inbox = Some(src);
                        }
                    }
                    Some(_) => {}
                    None => {
                        want.insert(t.label, Hint { thing: t.tid, index: t.index, servers: servers.collect(), via: None, inbox: Some(src) });
                    }
                }
                break;
            }
        }
        let gone: Vec<LabelId> = self.state.hints.iter().filter(|(l, h)| h.via.is_none() && !want.contains_key(l)).map(|(l, _)| *l).collect();
        for l in gone {
            self.state.remove_hint(&l);
        }
        for (l, h) in want {
            let old = self.state.hints.get(&l);
            if old.is_some_and(|x| x.via.is_some() || (x.thing, x.index, &x.servers, x.inbox) == (h.thing, h.index, &h.servers, h.inbox)) {
                continue;
            }
            self.state.add_hint(l, h);
        }
        Ok(())
    }

    /// Deletes the ciphertexts of opened inbox blobs naming a forgotten thing (they open under
    /// this node's own keys, and a grant carries its boxes: spec/permissions.md §3), then empties
    /// the work list. Their entries stay opened, never fetched again.
    pub(crate) fn forget_inbox(&mut self) -> Result<()> {
        if self.state.forget.is_empty() {
            return Ok(());
        }
        let things = self.state.forget.clone();
        let inbox: Vec<(LabelId, BlobId)> = self.state.entries.iter().filter(|(_, e)| matches!(e.kind, Kind::Inbox(_))).map(|(k, _)| *k).collect();
        let mut gone = Vec::new();
        for (l, b) in inbox {
            let Some(bytes) = self.engine.blob(&b)? else { continue };
            let Some((_, payload)) = self.open_inbox(&l, &bytes) else { continue };
            let names = payload.things.iter().any(|t| things.contains(&t.tid)) || osis_commit::CommitBlob::decode(&osis_base::encode(&payload.commit)).is_ok_and(|c| c.header.aspects.iter().any(|a| things.contains(&a.tid)));
            if names {
                gone.push(b);
            }
        }
        self.delete_blobs(&gone)?;
        for t in things {
            self.state.forget_done(&t);
        }
        self.state.flush(&mut self.engine)
    }

    /// A new head in a server's log: a child of the current one moves on, and reopens when its
    /// sync key is another (the server ended the open, spec/sync.md §5); anything else reopens.
    /// An open in flight learns the head itself (`accept_head` asks for the path after it).
    pub(crate) fn new_head(&mut self, conn: ConnId, l: LabelId, step: Step, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(lc) = self.lc(conn, &l) else { return Ok(()) };
        if matches!(lc.phase, super::Phase::Opening | super::Phase::Verifying | super::Phase::Registering) {
            return Ok(());
        }
        let cur = lc.head.clone();
        if cur.as_ref().is_some_and(|h| h.id() == step.id()) {
            return Ok(());
        }
        let (g, open) = (lc.group, lc.phase == super::Phase::Open);
        match cur {
            Some(h) if step.verify_child(&h).is_ok() => {
                let ended = open && step.keys.sync != h.keys.sync;
                self.record_steps(&g, &l, &[h, step.clone()], None)?;
                self.set_head(conn, l, step)?;
                if ended {
                    return self.reopen(conn, l, out);
                }
                Ok(())
            }
            _ => self.reopen(conn, l, out),
        }
    }

    /// A Sync ran through its last page: the pass at this server is complete.
    pub(crate) fn synced(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(server) = self.conns.get(&conn).map(|c| c.server) else { return Ok(()) };
        if let Some(lc) = self.lc_mut(conn, &l) {
            lc.syncing = false;
            lc.synced = true;
            lc.dirty = true;
        }
        self.bump_pass(server, l)?;
        self.fetch_waiting(conn, l, out)
    }

    pub(crate) fn bump_pass(&mut self, server: ServerKey, l: LabelId) -> Result<()> {
        // membership commits applied by this run count before the pass end
        self.engine_events()?;
        self.seq += 1;
        self.passes.insert((server, l), (self.seq, self.now()));
        Ok(())
    }

    /// Commits wait for pages: fetch the blobs their headers list that are not held (pages
    /// before apply, spec/sync.md §6; the chunks of other large values stay lazy).
    fn fetch_waiting(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<super::Action>) -> Result<()> {
        let waiting: Vec<osis_base::CommitId> = self.engine.pending().into_iter().filter(|(_, r)| *r == crate::Reason::WaitBlobs).map(|(c, _)| c).collect();
        let mut missing = BTreeSet::new();
        for c in waiting {
            let Some(bytes) = self.engine.commit_bytes(&c)? else { continue };
            let Ok(cb) = osis_commit::CommitBlob::decode(&bytes) else { continue };
            // asked of the label whether or not an entry was seen (an unstamped one that opened
            // under nothing is not kept, `drop_unvouched`)
            missing.extend(cb.header.chunks.iter().map(|ch| ch.blob).filter(|b| !self.engine.has_blob(b)));
        }
        self.fetch_on(conn, l, missing, out)
    }

    /// Fetches `ids` under `l` on `conn`, but those asked for already (on any connection) and
    /// those its server did not deliver (since it last announced them). Every fetch goes this
    /// way: a pass waits on the unopened entries in flight (`unsettled_sets`).
    pub(crate) fn fetch_on(&mut self, conn: ConnId, l: LabelId, ids: impl IntoIterator<Item = BlobId>, out: &mut Vec<super::Action>) -> Result<()> {
        let ids: Vec<BlobId> = ids.into_iter().filter(|b| !self.fetching(b)).collect();
        let Some(c) = self.conns.get_mut(&conn) else { return Ok(()) };
        let ids: Vec<BlobId> = ids.into_iter().filter(|b| !c.req.missing.contains(b) && c.req.fetching.insert(*b)).collect();
        if ids.is_empty() {
            return Ok(());
        }
        self.command(conn, Command::Fetch { label: l, ids }, out)
    }

    /// Entry `b` under `l` is no longer at `server`: once no server holds it, the entry goes
    /// (tombstoned) with the blob's record and bytes where nothing else needs them. Whether it
    /// went.
    pub(crate) fn absent_at(&mut self, server: Option<ServerKey>, l: LabelId, b: BlobId) -> Result<bool> {
        if let Some(s) = server {
            self.state.set_present(s, l, b, false);
        }
        if self.state.present_anywhere(&l, &b) {
            return Ok(false);
        }
        self.state.remove_entry(l, b);
        self.forget_blob(&b)?;
        self.forget_chunk(&b)?;
        Ok(true)
    }

    /// Drops a commit blob no label entry names any more whose deltas are not all held (its
    /// key and ciphertext: a dropped body's copies go, spec/commits.md §5).
    pub(crate) fn forget_blob(&mut self, b: &BlobId) -> Result<()> {
        let Some(r) = self.state.blobs.get(b) else { return Ok(()) };
        let dropped = self.engine.core.ix.commits.get(&r.commit).is_some_and(|m| r.parts.iter().any(|p| m.dropped.contains_key(&p.0)));
        let unused = !self.state.named(b);
        if dropped || unused && (r.cert || !self.engine.core.ix.commits.contains_key(&r.commit)) {
            // its entries stay (deletes at servers need no copy) with their wraps shredded
            let ls: Vec<LabelId> = self.state.labels_of(b);
            for l in ls {
                if let Some(mut e) = self.state.entries.get(&(l, *b)).cloned() {
                    e.wrap = [0; osis_crypto::WRAP_LEN];
                    e.stamp = None;
                    self.state.set_entry(l, *b, e);
                }
            }
            self.state.remove_blob(b);
            self.delete_blobs(&[*b])?;
        }
        Ok(())
    }

    /// The entries of commits with a part missing again (`Changed::undropped`: dropped under a
    /// cover since turned invalid, spec/permissions.md §5.2) whose bytes and wrap went with the
    /// drop: unopened again, so a pass fetches them where present (`refetch`), the reply bringing
    /// the wrap back. A body deleted everywhere comes back only as a holder's new upload. `None`:
    /// every commit (at start: a crash may have come between the engine's change and this).
    pub(crate) fn reopen_undropped(&mut self, commits: Option<&BTreeSet<osis_base::CommitId>>) {
        if commits.is_some_and(BTreeSet::is_empty) {
            return;
        }
        let ix = &self.engine.core.ix;
        let again = |c: &osis_base::CommitId, parts: &[(usize, usize)]| commits.is_none_or(|cs| cs.contains(c)) && ix.commits.get(c).is_some_and(|m| parts.iter().any(|p| m.missing.contains(&p.0)));
        let ids: Vec<(LabelId, BlobId)> = self.state.entries.iter().filter(|((_, b), e)| !self.state.blobs.contains_key(b) && matches!(&e.kind, Kind::Commit { commit, parts, .. } if again(commit, parts))).map(|(k, _)| *k).collect();
        for (l, b) in ids {
            if let Some(mut e) = self.state.entries.get(&(l, b)).cloned() {
                e.kind = Kind::Unknown;
                self.state.set_entry(l, b, e);
            }
        }
    }

    /// Drops the bytes of a chunk of dropped deltas once no label entry names it (spec/commits.md
    /// §5); while one does, its delete-key signature needs its prefix salt.
    pub(crate) fn forget_chunk(&mut self, b: &BlobId) -> Result<()> {
        // cheapest first: commit blobs have their own record, most deleted bytes are gone already
        if self.state.blobs.contains_key(b) || !self.engine.has_blob(b) || self.state.named(b) || !self.dropped_chunks(&BTreeSet::from([*b]))?.0.contains_key(b) {
            return Ok(());
        }
        self.delete_blobs(&[*b])
    }

    /// Forgets every commit blob holding a delta the engine dropped (purge, expiry, keep at
    /// most, compaction): key and ciphertext (spec/commits.md §5). Only those of `commits`
    /// when given (the commits a change may have dropped deltas of).
    pub(crate) fn forget_dropped(&mut self, commits: Option<&BTreeSet<osis_base::CommitId>>) -> Result<()> {
        let dropped = |s: &Self, r: &super::state::BlobRec| s.engine.core.ix.commits.get(&r.commit).is_some_and(|m| r.parts.iter().any(|p| m.dropped.contains_key(&p.0)));
        let fresh = std::mem::take(&mut self.state.new_blobs);
        let commits: Option<BTreeSet<osis_base::CommitId>> = commits.map(|c| c.union(&fresh).copied().collect());
        let commits = commits.as_ref();
        let ids: Vec<BlobId> = match commits {
            None => self.state.blobs.iter().filter(|(_, r)| dropped(self, r)).map(|(id, _)| *id).collect(),
            Some(cs) => cs.iter().flat_map(|c| self.state.by_commit.get(c).into_iter().flatten()).filter(|id| self.state.blobs.get(id).is_some_and(|r| dropped(self, r))).copied().collect(),
        };
        for id in ids {
            self.forget_blob(&id)?;
        }
        // chunks of dropped deltas no label entry names (never uploaded, or deleted everywhere)
        let listed: BTreeSet<BlobId> = match commits {
            None => self.engine.core.ix.commits.values().filter(|m| !m.dropped.is_empty()).flat_map(|m| m.view.chunks.iter().copied()).collect(),
            Some(cs) => cs.iter().filter_map(|c| self.engine.core.ix.commits.get(c)).filter(|m| !m.dropped.is_empty()).flat_map(|m| m.view.chunks.iter().copied()).collect(),
        };
        let held: BTreeSet<BlobId> = listed.into_iter().filter(|b| !self.state.blobs.contains_key(b) && !self.state.named(b) && self.engine.has_blob(b)).collect();
        if held.is_empty() {
            return Ok(());
        }
        let gone: Vec<BlobId> = self.dropped_chunks(&held)?.0.into_keys().collect();
        self.delete_blobs(&gone)
    }

    /// Fetches blobs by ID from an open label holding them (lazy chunk reads), but those in
    /// flight.
    pub fn fetch(&mut self, ids: &[BlobId]) -> Vec<super::Action> {
        let mut out = Vec::new();
        let mut todo: Vec<(ConnId, LabelId, Vec<BlobId>)> = Vec::new();
        for (conn, c) in &self.conns {
            for (l, lc) in &c.labels {
                if lc.phase != Phase::Open {
                    continue;
                }
                let v: Vec<BlobId> = ids.iter().filter(|b| self.state.is_present(&c.server, l, b)).copied().collect();
                if !v.is_empty() {
                    todo.push((*conn, *l, v));
                }
            }
        }
        // each blob from the first connection whose server may deliver it (`fetch_on` skips
        // those in flight, so those asked on an earlier one)
        for (conn, l, v) in todo {
            if let Err(e) = self.fetch_on(conn, l, v, &mut out) {
                self.diag(format!("fetch: {e}"));
            }
        }
        out
    }

    /// Fetches the blobs of one large value's tree that are not held yet (`Engine::tree_missing`:
    /// a read that missed a chunk; spec/sync.md §6), from the open labels holding them; empty
    /// when the tree is whole. Call again after they arrive: fetched nodes list more chunks.
    pub fn fetch_tree(&mut self, tid: &Tid, link: &osis_base::Link) -> Result<Vec<super::Action>> {
        let ids = self.engine.tree_missing(tid, link)?;
        Ok(self.fetch(&ids))
    }

    /// Fetches every entry not held yet from the servers holding it (lazy chunks, on demand).
    pub fn fetch_missing(&mut self) -> Vec<super::Action> {
        let ids: Vec<BlobId> = self.state.entries.iter().filter(|(_, e)| e.kind == Kind::Unknown).map(|((_, b), _)| *b).collect();
        let ids: Vec<BlobId> = ids.into_iter().filter(|b| !self.engine.has_blob(b)).collect();
        self.fetch(&ids)
    }

    /// Gained IDs the server lacks: upload the stamped entries held.
    pub(crate) fn want(&mut self, conn: ConnId, l: LabelId, ids: Vec<BlobId>, out: &mut Vec<super::Action>) -> Result<()> {
        let mut entries = Vec::new();
        for b in ids {
            let Some(e) = self.state.entries.get(&(l, b)).cloned() else { continue };
            let (Some(stamp), Some(blob)) = (e.stamp, self.engine.blob(&b)?) else { continue };
            entries.push(osis_proto::Entry { blob, wrap: e.wrap, stamp, replaces: Vec::new() });
        }
        if !entries.is_empty() {
            self.command(conn, Command::Upload { label: l, entries }, out)?;
        }
        Ok(())
    }

    /// Range reconciliation done: presence follows it; fetch what we lack, then a cursor-less
    /// metadata Sync for a fresh cursor.
    pub(crate) fn reconciled(&mut self, conn: ConnId, l: LabelId, need: Vec<BlobId>, have: Vec<BlobId>, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(server) = self.conns.get(&conn).map(|c| c.server) else { return Ok(()) };
        // held ephemeral entries the reconciled set listed: the peer lacks those in `have` (they
        // go up), holds the rest; one kept since and not seen there (from another server) goes up
        // too (another's presence entry: neither, `eph_upload`)
        if let Some(listed) = self.eph.reconciling.get(&(conn, l)) {
            let lacks: BTreeSet<BlobId> = have.iter().copied().collect();
            let held: Vec<BlobId> = SyncEngine::eph_entries_of(&self.eph, &l).map(|(b, _)| b).collect();
            let mut up = Vec::new();
            let mut holds = Vec::new();
            for b in held {
                if lacks.contains(&b) || !(listed.contains(&b) || self.eph.present.contains(&(server, l, b))) {
                    up.push(b);
                } else if listed.contains(&b) {
                    holds.push(b);
                }
            }
            for b in holds {
                self.eph.present.insert((server, l, b));
            }
            self.eph_upload_on(conn, l, &up, out)?;
        }
        for b in have {
            self.state.set_present(server, l, b, false);
        }
        // the server holds them now: undelivered before or not, asked again (like an announce)
        if let Some(c) = self.conns.get_mut(&conn) {
            for b in &need {
                c.req.missing.remove(b);
            }
        }
        let need: Vec<BlobId> = need.into_iter().filter(|b| !self.eph.unfit.contains(l, *b)).collect();
        self.fetch_on(conn, l, need, out)?;
        // a reconciliation after a start: the cursor stays (`sync_label`)
        if self.eph.reconciling.remove(&(conn, l)).is_some() {
            self.eph.reconciled.insert((server, l));
            return self.sync_label(conn, l, out);
        }
        if let Some(lc) = self.lc_mut(conn, &l) {
            lc.syncing = true;
        }
        self.command(conn, Command::Sync { label: l, cursor: None, inline_limit: 0, entries: Vec::new(), gained: Vec::new() }, out)
    }

    /// Upload or Sync statuses. Code 9 (signed under a key older than the head's) needs nothing
    /// here: the node uploads only where the label is open, so the new head comes by push or
    /// the next Sync (spec/sync.md §5), and its pass signs again under the new keys.
    pub(crate) fn entry_status(&mut self, conn: ConnId, l: LabelId, ids: Vec<BlobId>, codes: Vec<Code>, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(server) = self.conns.get(&conn).map(|c| c.server) else { return Ok(()) };
        let (ids, codes) = self.eph_status(conn, l, ids, codes, out)?;
        if ids.is_empty() {
            return Ok(());
        }
        let mut grew = false;
        for (b, code) in ids.into_iter().zip(codes) {
            let replaced = self.conns.get_mut(&conn).and_then(|c| {
                c.req.sent.remove(&(l, b));
                c.req.replacing.remove(&(l, b))
            });
            // what it replaced went with it (spec/sync.md §5); else those deletes may go again
            for p in replaced.into_iter().flatten() {
                if let Some(c) = self.conns.get_mut(&conn) {
                    c.req.deleting.remove(&(l, p));
                }
                if code == Code::OK {
                    self.absent_at(Some(server), l, p)?;
                    grew = true;
                }
            }
            if code == Code::STORAGE_CAP {
                self.capped.retain(|(s, l, b)| self.state.entries.contains_key(&(*l, *b)) && !self.state.is_present(s, l, b));
                // the bodies it would carry are judged again (`carried`), in a pass now
                if self.capped.insert((server, l, b)) {
                    self.state.touch(l, b);
                    grew = true;
                }
            } else {
                self.capped.remove(&(server, l, b));
            }
            match code {
                Code::OK => {
                    let new = !self.state.is_present(&server, &l, &b);
                    grew |= new;
                    self.state.set_present(server, l, b, true);
                    if new {
                        self.reached(&l, &b);
                    }
                    // a stamped upload of a deposited entry promoted it
                    self.state.set_deposited(server, l, b, false);
                }
                Code::TOMBSTONED => {
                    self.state.set_gone(server, l, b);
                    if let Some(lc) = self.lc_mut(conn, &l) {
                        lc.dirty = true;
                    }
                }
                Code::NOT_HEAD => {}
                c => self.diag(format!("upload refused: code {}", c.0)),
            }
            // a refused promotion waits again (`RELAY_MIN_MS`): co-writers refused alike (a step
            // registered meanwhile) would otherwise all send it at the next pass
            if code != Code::OK {
                let raw = self.raw_now();
                if let Some(t) = self.deposit_seen.get_mut(&(server, l, b)) {
                    *t = raw;
                }
            }
        }
        // carriers just went up (or were refused for the cap): deletions waiting for them may go now
        if grew && let Some(lc) = self.lc_mut(conn, &l) {
            lc.dirty = true;
        }
        Ok(())
    }

    /// Delete statuses; code 9 as for `entry_status`.
    pub(crate) fn delete_status(&mut self, conn: ConnId, l: LabelId, ids: Vec<BlobId>, codes: Vec<Code>) -> Result<()> {
        let Some(server) = self.conns.get(&conn).map(|c| c.server) else { return Ok(()) };
        let (ids, codes) = self.eph_delete_status(conn, l, ids, codes);
        for (b, code) in ids.into_iter().zip(codes) {
            // a timed delete is done once the server took it (spec/commits.md §5)
            let timed = self.conns.get_mut(&conn).is_some_and(|c| {
                c.req.deleting.remove(&(l, b));
                c.req.timed_sent.remove(&(l, b))
            });
            match code {
                Code::OK => {
                    if timed {
                        self.state.set_timed(server, l, b);
                        continue;
                    }
                    if self.state.timed.contains(&(server, l, b)) {
                        continue;
                    }
                    self.absent_at(Some(server), l, b)?;
                }
                Code::NOT_HEAD => {}
                c => self.diag(format!("delete refused: code {}", c.0)),
            }
        }
        // a replaced label is judged done after its deletions (`retire_at`): pass again
        if let Some(g) = self.lc(conn, &l).map(|x| x.group)
            && self.is_replaced(&g, &l)
            && let Some(lc) = self.lc_mut(conn, &l)
        {
            lc.dirty = true;
        }
        Ok(())
    }

    /// Entry `b` under `l` reached a server: when it holds a membership commit of this node,
    /// every label passes again (its held copies may go now, spec/sync.md §5).
    fn reached(&mut self, l: &LabelId, b: &BlobId) {
        let Some(Kind::Commit { commit, .. }) = self.state.entries.get(&(*l, *b)).map(|e| &e.kind) else { return };
        if self.own(commit) && self.engine.header(commit).is_some_and(|h| h.kind.is_membership()) {
            self.mark_dirty();
        }
    }

    /// A deposit's answer; `entries_left` only when the server checked its signature under the
    /// head (a stale one learns nothing: the head comes by the open connection, spec/sync.md §5).
    pub(crate) fn budget(&mut self, conn: ConnId, l: LabelId, b: BlobId, code: Code, entries_left: Option<u64>) -> Result<()> {
        let Some(c) = self.conns.get_mut(&conn) else { return Ok(()) };
        let server = c.server;
        c.req.sent.remove(&(l, b));
        if let Some(n) = entries_left
            && let Some(lc) = self.lc_mut(conn, &l)
        {
            lc.budget = Some(n);
        }
        // a queued deposit's answer
        let now = self.raw_now();
        if let Some(o) = self.outbox.get_mut(&(server, l, b)).filter(|o| o.sent.is_some()) {
            // refused for now (not registered yet, rate limit, budget full while the label's
            // writers are away, the server at a storage cap): sent again until taken or moot; signed by an earlier deposit key
            // (a refreshed deposit seed): the same bytes never verify, so signed again first
            o.tries = o.tries.saturating_add(1);
            o.sent = None;
            let tries = o.tries;
            let resigned = code == Code::NOT_HEAD && self.resign_deposit(&server, &l, &b)?;
            let retry = matches!(code, Code::UNKNOWN_LABEL | Code::RATE_LIMITED | Code::BUDGET_FULL | Code::STORAGE_CAP) || resigned;
            if retry && !self.deposit_moot(&server, &l, &b) {
                // retry_ms, doubling per refusal, at most DEPOSIT_RETRY_CAP_MS; re-signed: at once
                let back = if resigned { 0 } else { self.cfg.retry_ms.saturating_mul(1u64 << (tries - 1).min(20)).min(super::local::DEPOSIT_RETRY_CAP_MS) };
                if let Some(o) = self.outbox.get_mut(&(server, l, b)) {
                    o.after = now.saturating_add(back);
                }
            } else {
                if retry || code == Code::NOT_HEAD {
                    self.diag(format!("deposit under {l:?} moot after {tries} refusals (code {})", code.0));
                }
                self.outbox.remove(&(server, l, b));
                self.state.remove_out(&server, &l, &b);
            }
        }
        match code {
            Code::OK => {
                self.state.set_present(server, l, b, true);
                self.reached(&l, &b);
            }
            Code::NOT_HEAD => {}
            Code::TOMBSTONED => self.state.set_gone(server, l, b),
            c => self.diag(format!("deposit refused: code {}", c.0)),
        }
        Ok(())
    }
}
