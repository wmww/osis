//! What arrives (spec/sync.md §3, §6, §8, §9): log events and fetched entries become label
//! entries; blob bytes go to the store; commit blobs are unwrapped with the group's read secrets
//! (newest first), checked against their prefix and ingested, membership commits first; inbox
//! blobs are opened with the read KEM key of the actor whose inbox the label is; entries that
//! open with nothing held are retried when new secrets arrive; pages of waiting commits are
//! fetched before apply; signals are verified and fired.

use super::state::{BlobRec, Entry, Hint, Kind, ServerKey};
use super::{ConnId, Phase, RELINK_BACKOFF_MAX_MS, RELINK_BACKOFF_MS, SyncEngine};
use crate::error::Result;
use crate::labeling::open_commit;
use crate::Ingested;
use osis_base::{BlobId, Classified, CreationRecord, ErrorClass, LabelId, Role, Tid};
use osis_crypto::{Secret32, VerifyingKey, role_kem};
use osis_label::{PublishAuth, Step};
use osis_proto::{Code, Command, Cursor, Event as LogEvent};
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

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
        let server: Option<ServerKey> = conn.and_then(|c| self.conns.get(&c)).map(|c| c.server);
        let mut blobs = Vec::new();
        let mut touched = Vec::new();
        let mut fetch = Vec::new();
        // entries new here that no writer vouched for (a deposit, or a server's junk): no stamp
        // under the head's write key, or before a head is known any step's this node knows (a
        // server cannot make one; a superseded step's key may be a removed writer's)
        let mut unvouched = Vec::new();
        let head_write = conn.and_then(|c| self.conns.get(&c)).and_then(|c| c.labels.get(&l)).and_then(|x| x.head.as_ref()).map(|h| h.keys.write);
        let mut writers: Vec<osis_crypto::VerifyingKey> = conn.and_then(|c| self.conns.get(&c)).and_then(|c| c.labels.get(&l)).map(|x| x.writers.iter().copied().chain(x.head.as_ref().map(|h| h.keys.write)).collect()).unwrap_or_default();
        if server.is_some() && events.iter().any(|e| matches!(e, LogEvent::Added { .. }))
            && let Some(g) = self.group_of(&l)
            && let Some(gl) = self.group_label(&g, &l)
        {
            for (st, _) in gl.steps.values() {
                if !writers.contains(&st.keys.write) {
                    writers.push(st.keys.write);
                }
            }
        }
        // deleted blobs that are no commit blob: chunks a live value may still link
        let mut lost = BTreeSet::new();
        for ev in events {
            match ev {
                LogEvent::Added { blob_id, blob, wrap, stamp } => {
                    let vouched = stamp.is_some_and(|st| match &head_write {
                        Some(w) => osis_label::verify_stamp(w, &l, &blob_id, &wrap, &st).is_ok(),
                        None => writers.iter().any(|w| osis_label::verify_stamp(w, &l, &blob_id, &wrap, &st).is_ok()),
                    });
                    if let Some(s) = server {
                        self.state.set_present(s, l, blob_id, true);
                        self.state.set_deposited(s, l, blob_id, stamp.is_none());
                    }
                    // a stamp counts only if it verifies under the head's write key (it is relayed)
                    let head = conn.and_then(|c| self.conns.get(&c)).and_then(|c| c.labels.get(&l)).and_then(|x| x.head.clone());
                    let stamp = stamp.filter(|st| match &head {
                        Some(h) => osis_label::verify_stamp(&h.keys.write, &l, &blob_id, &wrap, st).is_ok(),
                        // a bundle's stamps were checked against its path by the importer
                        None => conn.is_none(),
                    });
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
                            self.fetching.remove(&blob_id);
                            blobs.push((blob_id, b));
                        }
                        None if !self.engine.has_blob(&blob_id) => fetch.push(blob_id),
                        None => {}
                    }
                    touched.push(blob_id);
                }
                LogEvent::Deleted(b) => {
                    if let Some(s) = server {
                        self.state.set_present(s, l, b, false);
                    }
                    if !self.state.present_anywhere(&l, &b) {
                        // gone from every server of the label: a chunk an own commit may link
                        if !self.state.blobs.contains_key(&b) {
                            lost.insert(b);
                        }
                        self.state.remove_entry(l, b);
                        self.forget_blob(&b)?;
                        self.forget_chunk(&b)?;
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
            let want: Vec<BlobId> = fetch.into_iter().filter(|b| self.state.entries.get(&(l, *b)).is_some_and(|e| osis_label::unwrap_any(secrets.iter(), b, &e.wrap).is_some())).filter(|b| self.fetching.insert(*b, c).is_none()).collect();
            if !want.is_empty() {
                self.command(c, Command::Fetch { label: l, ids: want }, out)?;
            }
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
                    self.fetching.remove(b);
                }
                held -= 1;
                over += 1;
            }
        }
        if over > 0 {
            self.diag(format!("label {l:?}: {over} unopened unstamped entries over the cap dropped"));
        }
        if !gone.is_empty() {
            self.engine.run(|tx| {
                for b in &gone {
                    tx.txn.delete_blob(b);
                }
                Ok(())
            })?;
        }
        Ok(())
    }

    /// Held read secrets of a group, newest first; then those derived from its owner's (a
    /// thing that got secrets of its own, or one owned by a key actor this node holds: the
    /// rotation that gave it its own is wrapped under the derived epoch, spec/crypto.md §5).
    pub(crate) fn read_secrets(&self, g: &Tid) -> Vec<Secret32> {
        let mut v: Vec<Secret32> = self.engine.epochs(g).map(|e| e.read.held_newest_first().into_iter().map(|(_, s)| s.clone()).collect()).unwrap_or_default();
        // the owner's epochs; a thing whose `/created` is not here yet (a recovery card's
        // person) may be owned by any key actor held
        let owners: Vec<osis_keys::ActorEpochs> = match self.engine.core.created(g) {
            Some(CreationRecord::Thing { owner, .. }) => self.engine.epochs(owner).or_else(|| self.engine.core.key_actors.get(owner).map(|id| osis_keys::ActorEpochs::key_actor(id.seed()))).into_iter().collect(),
            Some(CreationRecord::KeyActor { .. }) => Vec::new(),
            None => self.engine.core.key_actors.values().map(|id| osis_keys::ActorEpochs::key_actor(id.seed())).collect(),
        };
        for oe in owners {
            for (_, s) in osis_keys::ActorEpochs::derived(&oe, g).read.held_newest_first() {
                if !v.iter().any(|x| x.expose() == s.expose()) {
                    v.push(s.clone());
                }
            }
        }
        v
    }

    /// Actors whose inbox is `l`.
    pub(crate) fn inbox_actors(&mut self, l: &LabelId) -> Vec<Tid> {
        self.inbox_of(l).into_iter().map(|(a, _)| a).collect()
    }

    /// Actors whose inbox is `l`, with their held read KEM secrets.
    fn inbox_of(&mut self, l: &LabelId) -> Vec<(Tid, Vec<Secret32>)> {
        let actors: Vec<Tid> = self.engine.core.secrets.keys().copied().collect();
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
        Ok(())
    }

    fn secrets_count(&self) -> usize {
        self.engine.core.secrets.values().map(|e| e.read.held_newest_first().len() + e.write.held_newest_first().len() + e.admin.held_newest_first().len()).sum()
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
        for (actor, keys) in self.inbox_of(&l) {
            for s in keys {
                let kem = role_kem(&s);
                if let Ok((_, payload)) = osis_label::open_inbox_blob(&bytes, &actor, &kem) {
                    let pt = osis_base::encode(&payload.commit);
                    if let Ok(c) = osis_commit::CommitBlob::decode(&pt) {
                        self.engine.note_delete_hints(c.id(), &payload.things)?;
                    }
                    for t in &payload.things {
                        if self.engine.labels_of(&t.tid).iter().all(|x| x.id != t.label) {
                            // a sender's word: servers only, never a node to dial (`peer://`)
                            self.state.add_hint(t.label, Hint { thing: t.tid, servers: t.servers.iter().filter(|a| !super::peers::is_peer(a)).cloned().collect(), via: None });
                        }
                    }
                    let c = osis_commit::CommitBlob::decode(&pt).ok();
                    e.kind = Kind::Inbox(c.as_ref().map(|c| c.id()));
                    self.state.set_entry(l, b, e);
                    if let Some(c) = c {
                        commits.push((pt, c));
                    }
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// The aspect indexes of the commit inbox blob `b` under `l` carries and the things it names
    /// (it opens again under the held keys of an actor whose inbox `l` is), if its bytes are
    /// held.
    pub(crate) fn inbox_parts(&mut self, l: &LabelId, b: &BlobId) -> Result<Option<(BTreeSet<usize>, Vec<Tid>)>> {
        let Some(bytes) = self.engine.blob(b)? else { return Ok(None) };
        let opened = self.inbox_of(l).into_iter().flat_map(|(a, keys)| keys.into_iter().map(move |s| (a, s))).find_map(|(a, s)| osis_label::open_inbox_blob(&bytes, &a, &role_kem(&s)).ok());
        let Some((_, payload)) = opened else { return Ok(None) };
        let Ok(c) = osis_commit::CommitBlob::decode(&osis_base::encode(&payload.commit)) else { return Ok(None) };
        Ok(Some((c.parts.iter().map(|p| p.ai).collect(), payload.things.iter().map(|t| t.tid).collect())))
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
            let opened = self.inbox_of(&l).into_iter().flat_map(|(a, keys)| keys.into_iter().map(move |s| (a, s))).find_map(|(a, s)| osis_label::open_inbox_blob(&bytes, &a, &role_kem(&s)).ok());
            let Some((_, payload)) = opened else { continue };
            let names = payload.things.iter().any(|t| things.contains(&t.tid)) || osis_commit::CommitBlob::decode(&osis_base::encode(&payload.commit)).is_ok_and(|c| c.header.aspects.iter().any(|a| things.contains(&a.tid)));
            if names {
                gone.push(b);
            }
        }
        if !gone.is_empty() {
            self.engine.run(|tx| {
                for b in &gone {
                    tx.txn.delete_blob(b);
                }
                Ok(())
            })?;
        }
        for t in things {
            self.state.forget_done(&t);
        }
        self.state.flush(&mut self.engine)
    }

    /// A new head in a server's log: a child of the current one moves on; anything else reopens.
    pub(crate) fn new_head(&mut self, conn: ConnId, l: LabelId, step: Step, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(lc) = self.lc(conn, &l) else { return Ok(()) };
        let cur = lc.head.clone();
        if cur.as_ref().is_some_and(|h| h.id() == step.id()) {
            return Ok(());
        }
        let (g, index) = (lc.group, lc.index.unwrap_or(0));
        match cur {
            Some(h) if step.verify_child(&h).is_ok() => {
                self.record_steps(&g, &l, &[h, step.clone()], None)?;
                let keys = self.engine.head_keys(&g, index, &step)?;
                if let Some(s) = self.conns.get(&conn).map(|c| c.server) {
                    self.state.set_head(s, l, &step);
                }
                if let Some(lc) = self.lc_mut(conn, &l) {
                    lc.head = Some(step);
                    lc.keys = keys;
                    lc.dirty = true;
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
        self.passes.insert((server, l), self.seq);
        Ok(())
    }

    /// Commits wait for pages: fetch the blobs their headers list that are not held (pages
    /// before apply, spec/sync.md §6; the chunks of other large values stay lazy).
    fn fetch_waiting(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<super::Action>) -> Result<()> {
        let waiting: Vec<osis_base::CommitId> = self.engine.pending().into_iter().filter(|(_, r)| *r == crate::Reason::WaitBlobs).map(|(c, _)| c).collect();
        let mut missing = Vec::new();
        for c in waiting {
            let Some(bytes) = self.engine.commit_bytes(&c)? else { continue };
            let Ok(cb) = osis_commit::CommitBlob::decode(&bytes) else { continue };
            for ch in &cb.header.chunks {
                // asked of the label whether or not an entry was seen (an unstamped one that
                // opened under nothing is not kept, `drop_unvouched`)
                if !self.missing.contains(&(conn, ch.blob)) && !self.engine.has_blob(&ch.blob) && self.fetching.insert(ch.blob, conn).is_none() {
                    missing.push(ch.blob);
                }
            }
        }
        if !missing.is_empty() {
            self.command(conn, Command::Fetch { label: l, ids: missing }, out)?;
        }
        Ok(())
    }

    /// Drops a commit blob no label entry names any more whose deltas are not all held (its
    /// key and ciphertext: a dropped body's copies go, spec/commits.md §5).
    pub(crate) fn forget_blob(&mut self, b: &BlobId) -> Result<()> {
        let Some(r) = self.state.blobs.get(b) else { return Ok(()) };
        let dropped = self.engine.core.commits.get(&r.commit).is_some_and(|m| r.parts.iter().any(|p| m.dropped.contains(p)));
        let unused = !self.state.named(b);
        if dropped || unused && (r.cert || !self.engine.core.commits.contains_key(&r.commit)) {
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
            let id = *b;
            self.engine.run(|tx| {
                tx.txn.delete_blob(&id);
                Ok(())
            })?;
        }
        Ok(())
    }

    /// Drops the bytes of a chunk of dropped deltas once no label entry names it (spec/commits.md
    /// §5); while one does, its delete-key signature needs its prefix salt.
    pub(crate) fn forget_chunk(&mut self, b: &BlobId) -> Result<()> {
        // cheapest first: commit blobs have their own record, most deleted bytes are gone already
        if self.state.blobs.contains_key(b) || !self.engine.has_blob(b) || self.state.named(b) || !self.dropped_chunks(&BTreeSet::from([*b]))?.0.contains_key(b) {
            return Ok(());
        }
        let id = *b;
        self.engine.run(|tx| {
            tx.txn.delete_blob(&id);
            Ok(())
        })
    }

    /// Forgets every commit blob holding a delta the engine dropped (purge, expiry, keep at
    /// most, compaction): key and ciphertext (spec/commits.md §5). Only those of `commits`
    /// when given (the commits a change may have dropped deltas of).
    pub(crate) fn forget_dropped(&mut self, commits: Option<&BTreeSet<osis_base::CommitId>>) -> Result<()> {
        let dropped = |s: &Self, r: &super::state::BlobRec| s.engine.core.commits.get(&r.commit).is_some_and(|m| r.parts.iter().any(|p| m.dropped.contains(p)));
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
            None => self.engine.core.commits.values().filter(|m| !m.dropped.is_empty()).flat_map(|m| m.view.chunks.iter().copied()).collect(),
            Some(cs) => cs.iter().filter_map(|c| self.engine.core.commits.get(c)).filter(|m| !m.dropped.is_empty()).flat_map(|m| m.view.chunks.iter().copied()).collect(),
        };
        let held: BTreeSet<BlobId> = listed.into_iter().filter(|b| !self.state.blobs.contains_key(b) && !self.state.named(b) && self.engine.has_blob(b)).collect();
        if held.is_empty() {
            return Ok(());
        }
        let gone: Vec<BlobId> = self.dropped_chunks(&held)?.0.into_keys().collect();
        self.engine.run(|tx| {
            for b in &gone {
                tx.txn.delete_blob(b);
            }
            Ok(())
        })
    }

    /// Fetches blobs by ID from every open label holding them (lazy chunk reads).
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
        let mut asked = BTreeSet::new();
        for (conn, l, v) in todo {
            let v: Vec<BlobId> = v.into_iter().filter(|b| asked.insert(*b)).collect();
            if !v.is_empty()
                && let Err(e) = self.command(conn, Command::Fetch { label: l, ids: v }, &mut out)
            {
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
        let ids: Vec<BlobId> = ids.into_iter().filter(|b| !self.fetching.contains_key(b)).collect();
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
            entries.push(osis_proto::Entry { blob, wrap: e.wrap, stamp });
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
        for b in have {
            self.state.set_present(server, l, b, false);
        }
        if !need.is_empty() {
            self.command(conn, Command::Fetch { label: l, ids: need }, out)?;
        }
        if let Some(lc) = self.lc_mut(conn, &l) {
            lc.syncing = true;
        }
        self.command(conn, Command::Sync { label: l, cursor: None, inline_limit: 0, entries: Vec::new(), gained: Vec::new() }, out)
    }

    /// Upload or Sync statuses.
    pub(crate) fn entry_status(&mut self, conn: ConnId, l: LabelId, ids: Vec<BlobId>, codes: Vec<Code>, head: Option<Step>, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(server) = self.conns.get(&conn).map(|c| c.server) else { return Ok(()) };
        let mut stale = false;
        let mut grew = false;
        for (b, code) in ids.into_iter().zip(codes) {
            self.sent.remove(&(conn, l, b));
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
                Code::NOT_HEAD => stale = true,
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
        // carriers just went up: deletions waiting for them may go now
        if grew && let Some(lc) = self.lc_mut(conn, &l) {
            lc.dirty = true;
        }
        if stale && let Some(h) = head {
            self.new_head(conn, l, h, out)?;
        }
        Ok(())
    }

    pub(crate) fn delete_status(&mut self, conn: ConnId, l: LabelId, ids: Vec<BlobId>, codes: Vec<Code>, head: Option<Step>, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(server) = self.conns.get(&conn).map(|c| c.server) else { return Ok(()) };
        let mut stale = false;
        for (b, code) in ids.into_iter().zip(codes) {
            // a timed delete is done once the server took it (spec/commits.md §5)
            let timed = self.timed_sent.remove(&(conn, l, b));
            self.deleting.remove(&(conn, l, b));
            match code {
                Code::OK => {
                    if timed {
                        self.state.set_timed(server, l, b);
                        continue;
                    }
                    if self.state.timed.contains(&(server, l, b)) {
                        continue;
                    }
                    self.state.set_present(server, l, b, false);
                    if !self.state.present_anywhere(&l, &b) {
                        self.state.remove_entry(l, b);
                        self.forget_blob(&b)?;
                        self.forget_chunk(&b)?;
                    }
                }
                Code::NOT_HEAD => stale = true,
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
        if stale && let Some(h) = head {
            self.new_head(conn, l, h, out)?;
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

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn budget(&mut self, conn: ConnId, l: LabelId, b: BlobId, code: Code, entries_left: u64, head: Option<Step>, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(server) = self.conns.get(&conn).map(|c| c.server) else { return Ok(()) };
        self.sent.remove(&(conn, l, b));
        if let Some(lc) = self.lc_mut(conn, &l) {
            lc.budget = Some(entries_left);
        }
        if let Some((_, mut o)) = self.inbox_sent.remove(&(server, b)) {
            let retry = matches!(code, Code::UNKNOWN_LABEL | Code::RATE_LIMITED | Code::BUDGET_FULL | Code::NOT_HEAD);
            o.tries += 1;
            if !retry {
                self.state.remove_out(&server, &b);
            } else if o.tries > super::local::MAX_INBOX_TRIES {
                self.diag(format!("deposit under {l:?} dropped after {} refusals (code {})", o.tries - 1, code.0));
                self.state.remove_out(&server, &b);
            } else {
                // retry_ms, doubling per refusal, at most an hour
                let back = self.cfg.retry_ms.saturating_mul(1u64 << (o.tries - 1).min(20)).min(3_600_000);
                o.after = self.raw_now().saturating_add(back);
                self.outbox.push(o);
            }
        }
        match code {
            Code::OK => {
                self.state.set_present(server, l, b, true);
                self.reached(&l, &b);
            }
            Code::NOT_HEAD => {
                if let Some(h) = head {
                    self.new_head(conn, l, h, out)?;
                }
            }
            Code::TOMBSTONED => self.state.set_gone(server, l, b),
            c => self.diag(format!("deposit refused: code {}", c.0)),
        }
        Ok(())
    }

    /// A signal under `l` (spec/sync.md §9): opened with the label's read secrets, the sender's
    /// signature and its write authority on the thing verified like a commit's; dropped when
    /// its chain is unknown or targeted at another node; never stored.
    pub(crate) fn signal_in(&mut self, l: LabelId, blob: &[u8], wrap: &[u8; osis_crypto::WRAP_LEN], _auth: &PublishAuth) -> Result<()> {
        let Some(g) = self.group_of(&l) else { return Ok(()) };
        let id = osis_label::blob_id(blob);
        let Some((_, key)) = osis_label::unwrap_any(self.read_secrets(&g).iter(), &id, wrap) else { return Ok(()) };
        let Ok((body, sig)) = osis_label::open_signal(blob, &key) else { return Ok(()) };
        if body.target.is_some_and(|t| t != self.engine.tid()) {
            return Ok(());
        }
        // a replay (a server or relay re-sending a captured signal later) fires nothing
        let (now, at) = (self.engine.now().0, body.ts.wall_ms().0);
        if at.saturating_add(osis_base::format::MAX_DRIFT_MS) < now || at > now.saturating_add(osis_base::format::MAX_DRIFT_MS) {
            return Ok(());
        }
        let Some(CreationRecord::KeyActor { public_key, .. }) = self.engine.core.created(&body.node).cloned() else { return Ok(()) };
        let Ok(pk) = <[u8; 32]>::try_from(public_key.as_slice()) else { return Ok(()) };
        let Ok(vk) = VerifyingKey::from_bytes(&pk) else { return Ok(()) };
        if body.verify(&vk, &sig).is_err() {
            return Ok(());
        }
        let ts = body.ts;
        if crate::engine::write::role_of(&self.engine.core, &body.node, &body.tid, ts) < Some(Role::Write) {
            return Ok(());
        }
        if body.actor != body.node && crate::engine::write::role_of(&self.engine.core, &body.node, &body.actor, ts) < Some(Role::Write) {
            return Ok(());
        }
        self.engine.core.events.queue(crate::Event::Signal { tid: body.tid, kind: body.kind.clone(), from: body.node, actor: body.actor, ts: body.ts, target: body.target, value: body.value.clone() });
        self.engine.core.events.flush();
        self.signals.push(body);
        Ok(())
    }
}

