//! What arrives (spec/sync.md §3, §6, §8, §9): log events and fetched entries become label
//! entries; blob bytes go to the store; commit blobs are unwrapped with the group's read secrets
//! (newest first), checked against their prefix and ingested, membership commits first; inbox
//! blobs are opened with the read KEM key of the actor whose inbox the label is; entries that
//! open with nothing held are retried when new secrets arrive; pages of waiting commits are
//! fetched before apply; signals are verified and fired.

use super::state::{BlobRec, Entry, Hint, Kind, ServerKey};
use super::{ConnId, Phase, SyncEngine};
use crate::engine::Engine;
use crate::error::Result;
use crate::labeling::open_commit;
use osis_core::{BlobId, CreationRecord, LabelId, Role, Tid};
use osis_crypto::{Secret32, VerifyingKey, role_kem};
use osis_label::{PublishAuth, Step};
use osis_proto::{Code, Command, Cursor, Event as LogEvent};
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

/// Rounds of "new secrets opened more entries" per batch.
const MAX_ROUNDS: usize = 16;

impl Engine {
    /// Stores blob ciphertexts (pages, chunks, commit blobs) by ID.
    pub(crate) fn put_blobs(&mut self, blobs: Vec<(BlobId, Vec<u8>)>) -> Result<()> {
        if blobs.is_empty() {
            return Ok(());
        }
        self.run(|tx| {
            for (id, b) in blobs {
                if osis_label::blob_id(&b) == id && tx.txn.get_blob(&id)?.is_none() {
                    tx.txn.put_blob(&id, b)?;
                }
            }
            Ok(())
        })
    }

    pub(crate) fn has_blob(&mut self, id: &BlobId) -> bool {
        let id = *id;
        self.run(|tx| Ok(tx.txn.get_blob(&id)?.is_some())).unwrap_or(false)
    }
}

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

    /// Log events of a Sync reply, a push, a fetch or a bundle (`conn` none).
    pub(crate) fn log_events(&mut self, conn: Option<ConnId>, l: LabelId, events: Vec<LogEvent>, cursor: Option<Cursor>, out: &mut Vec<super::Action>) -> Result<()> {
        let server: Option<ServerKey> = conn.and_then(|c| self.conns.get(&c)).map(|c| c.server);
        let mut blobs = Vec::new();
        let mut touched = Vec::new();
        let mut fetch = Vec::new();
        for ev in events {
            match ev {
                LogEvent::Added { blob_id, blob, wrap, stamp } => {
                    if let Some(s) = server {
                        self.state.set_present(s, l, blob_id, true);
                    }
                    let mut e = self.state.entries.get(&(l, blob_id)).cloned().unwrap_or(Entry { wrap, stamp, cert: false, kind: Kind::Unknown });
                    if stamp.is_some() || e.wrap != wrap {
                        e.wrap = wrap;
                        e.stamp = stamp;
                    }
                    self.state.set_entry(l, blob_id, e);
                    match blob {
                        Some(b) => blobs.push((blob_id, b)),
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
                        self.state.remove_entry(l, b);
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
        if let (Some(s), Some(c)) = (server, cursor) {
            self.state.set_cursor(s, l, Some(c));
        }
        self.engine.put_blobs(blobs)?;
        self.open_entries(l, &touched)?;
        // commit blobs announced without bytes are fetched now; the rest (chunks) lazily
        if let Some(c) = conn {
            let g = self.group_of(&l);
            let secrets = g.map(|g| self.read_secrets(&g)).unwrap_or_default();
            let want: Vec<BlobId> = fetch.into_iter().filter(|b| self.state.entries.get(&(l, *b)).is_some_and(|e| osis_label::unwrap_any(secrets.iter(), b, &e.wrap).is_some())).collect();
            if !want.is_empty() {
                self.command(c, Command::Fetch { label: l, ids: want }, out)?;
            }
        }
        Ok(())
    }

    /// Held read secrets of a group, newest first.
    pub(crate) fn read_secrets(&self, g: &Tid) -> Vec<Secret32> {
        self.engine.epochs(g).map(|e| e.read.held_newest_first().into_iter().map(|(_, s)| s.clone()).collect()).unwrap_or_default()
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
        self.engine.core.secrets.values().map(|e| e.read.held().count() + e.write.held().count() + e.admin.held().count()).sum()
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
                    e.kind = Kind::Commit { commit, parts };
                    self.state.set_entry(l, b, e);
                    commits.push((pt, c));
                }
                Err(err) => self.diag(format!("blob {b:?}: {err}")),
            }
            return Ok(());
        }
        for (actor, keys) in self.inbox_of(&l) {
            for s in keys {
                let kem = role_kem(&s);
                if let Ok((_, payload)) = osis_label::open_inbox_blob(&bytes, &actor, &kem) {
                    let pt = osis_core::encode(&payload.commit);
                    for t in &payload.things {
                        if self.engine.group_labels(&t.tid).unwrap_or_default().iter().all(|x| x.id != t.label) {
                            self.state.add_hint(t.label, Hint { thing: t.tid, servers: t.servers.clone() });
                        }
                    }
                    e.kind = Kind::Inbox;
                    self.state.set_entry(l, b, e);
                    if let Ok(c) = osis_commit::CommitBlob::decode(&pt) {
                        commits.push((pt, c));
                    }
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// A new head in a server's log: a child of the current one moves on; anything else reopens.
    fn new_head(&mut self, conn: ConnId, l: LabelId, step: Step, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(lc) = self.conns.get(&conn).and_then(|c| c.labels.get(&l)) else { return Ok(()) };
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
                if let Some(lc) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&l)) {
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
        if let Some(lc) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&l)) {
            lc.syncing = false;
            lc.synced = true;
            lc.dirty = true;
        }
        self.bump_pass(server, l);
        self.fetch_waiting(conn, l, out)
    }

    pub(crate) fn bump_pass(&mut self, server: ServerKey, l: LabelId) {
        self.seq += 1;
        self.passes.insert((server, l), self.seq);
    }

    /// Commits wait for pages: fetch every entry of the label whose bytes are not held (pages
    /// before apply, spec/sync.md §6).
    fn fetch_waiting(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<super::Action>) -> Result<()> {
        if !self.engine.pending().iter().any(|(_, r)| *r == crate::Reason::WaitBlobs) {
            return Ok(());
        }
        let missing: Vec<BlobId> = self.state.entries.iter().filter(|((x, _), e)| *x == l && e.kind == Kind::Unknown).map(|((_, b), _)| *b).collect();
        let missing: Vec<BlobId> = missing.into_iter().filter(|b| !self.engine.has_blob(b)).collect();
        if !missing.is_empty() {
            self.command(conn, Command::Fetch { label: l, ids: missing }, out)?;
        }
        Ok(())
    }

    /// Drops a commit blob no label entry names any more whose deltas are not all held (its
    /// key and ciphertext: a dropped body's copies go, spec/commits.md §5).
    pub(crate) fn forget_blob(&mut self, b: &BlobId) -> Result<()> {
        if self.state.entries.keys().any(|(_, x)| x == b) {
            return Ok(());
        }
        let Some(r) = self.state.blobs.get(b) else { return Ok(()) };
        let gone = self.engine.core.commits.get(&r.commit).is_none_or(|m| r.parts.iter().any(|p| m.dropped.contains(p)));
        if gone || r.cert {
            self.state.remove_blob(b);
            let id = *b;
            self.engine.run(|tx| {
                tx.txn.delete_blob(&id);
                Ok(())
            })?;
        }
        Ok(())
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
        if let Some(lc) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&l)) {
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
            match code {
                Code::OK => {
                    grew |= !self.state.is_present(&server, &l, &b);
                    self.state.set_present(server, l, b, true);
                }
                Code::TOMBSTONED => {
                    self.state.set_gone(server, l, b);
                    if let Some(lc) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&l)) {
                        lc.dirty = true;
                    }
                }
                Code::NOT_HEAD => stale = true,
                c => self.diag(format!("upload refused: code {}", c.0)),
            }
        }
        // carriers just went up: deletions waiting for them may go now
        if grew && let Some(lc) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&l)) {
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
            match code {
                Code::OK => {
                    if self.state.timed.contains(&(server, l, b)) {
                        continue;
                    }
                    self.state.set_present(server, l, b, false);
                    if !self.state.present_anywhere(&l, &b) {
                        self.state.remove_entry(l, b);
                        self.forget_blob(&b)?;
                    }
                }
                Code::NOT_HEAD => stale = true,
                c => self.diag(format!("delete refused: code {}", c.0)),
            }
        }
        if stale && let Some(h) = head {
            self.new_head(conn, l, h, out)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn budget(&mut self, conn: ConnId, l: LabelId, b: BlobId, code: Code, entries_left: u64, head: Option<Step>, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(server) = self.conns.get(&conn).map(|c| c.server) else { return Ok(()) };
        if let Some(lc) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&l)) {
            lc.budget = Some(entries_left);
        }
        match code {
            Code::OK => self.state.set_present(server, l, b, true),
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
        self.engine.core.events.queue(crate::Event::Signal { kind: body.kind.clone(), from: body.node, value: body.value.clone() });
        self.engine.core.events.flush();
        self.signals.push(body);
        Ok(())
    }
}

