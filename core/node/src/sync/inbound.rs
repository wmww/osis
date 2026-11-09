//! What arrives (spec/sync.md §3, §6, §8, §9): log events and fetched entries become label
//! entries; blob bytes go to the store; commit blobs are unwrapped with the group's read secrets
//! (newest first), checked against their prefix and ingested, role commits first; inbox
//! blobs are opened with the read KEM key of the actor whose inbox the label is; entries that
//! open with nothing held are retried when new secrets arrive; pages of waiting commits are
//! fetched before apply; ephemeral entries go to the ephemeral lane (`ephemeral`).

use super::state::{BlobRec, Entry, Hint, Kind, HostKey};
use super::{ConnId, Phase, RELINK_BACKOFF_MAX_MS, RELINK_BACKOFF_MS, SyncEngine};
use crate::error::Result;
use crate::Ingested;
use osis_base::{BlobId, Classified, CommitId, ErrorClass, LabelId, Tid};
use osis_crypto::{Secret32, VerifyingKey, role_kem};
use osis_label::Step;
use osis_proto::{Code, Command, Cursor, Event as LogEvent};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// An opened inbox blob: its prefix expiry (none: never), the aspect indexes its commit
/// carries, the things its payload names, and its commit's author and signature (an invite
/// request is judged by them).
#[derive(Clone, Debug)]
pub(crate) struct Opened {
    pub until: u64,
    pub ais: BTreeSet<usize>,
    pub things: Vec<osis_label::InboxThing>,
    pub author: Tid,
    pub epoch: Option<osis_base::CommitId>,
    pub sigs: osis_commit::Sigs,
    /// Per thing, the holders the commit names on it, unverified (`Engine::hint_actors`).
    pub named: BTreeMap<Tid, Vec<Tid>>,
}

impl Opened {
    fn new(prefix: &osis_label::Prefix, c: &osis_commit::CommitBlob, things: Vec<osis_label::InboxThing>) -> Opened {
        Opened { until: prefix.expiry().map_or(u64::MAX, |w| w.0), ais: c.parts.iter().map(|p| p.ai).collect(), things, author: c.header.author, epoch: c.header.epoch, sigs: c.sigs.clone(), named: osis_engine::apply::keys::inbox_named(c, &c.id()) }
    }
}

/// What an unjudgeable commit awaits (`Kind::Awaits`).
fn awaited(r: &crate::Reason) -> Tid {
    match r {
        crate::Reason::MissingChain(t) | crate::Reason::UnknownCreated(t) => *t,
        _ => Tid::from_bytes([0; 15]),
    }
}

/// Whether a commit carries a `created.0` part (what the rest of a batch is judged by).
fn carries_creation(c: &osis_commit::CommitBlob) -> bool {
    c.header.aspects.iter().any(|a| a.ak.as_str() == "created.0")
}

/// Rounds of "new secrets opened more entries" per batch.
/// A commit blob an entry opened to (`open_one`), to ingest: a label entry's with its blob and
/// size (a memory commit is ingested within its label's room), or an inbox blob's.
pub(crate) struct ToIngest {
    pub label: LabelId,
    pub blob: BlobId,
    /// Its encoded bytes.
    pub size: usize,
    pub plaintext: Vec<u8>,
    pub commit: osis_commit::CommitBlob,
}

const MAX_ROUNDS: usize = 16;

/// The chain commits an inbox payload carries (spec/wire.md §9) that decode as commit blobs, each
/// cut to its chain deltas. Admission judges the blob's commit, which anyone can name: a box or a
/// `label.0` here would be an invite nobody was asked about; a bare edge is the limit (a status
/// row at worst).
fn chain_commits(chain: Vec<osis_base::Value>) -> Vec<(Vec<u8>, osis_commit::CommitBlob)> {
    // each value freed before its plaintext decodes: never two decoded copies of a stranger's blob
    chain.into_iter().filter_map(|v| {
        let plain = osis_base::encode(&v);
        drop(v);
        let mut c = osis_commit::CommitBlob::decode(&plain).ok()?;
        let aspects = &c.header.aspects;
        let parts = c.parts.iter().filter(|x| aspects.get(x.ai).is_some_and(|a| matches!(a.ak.as_str(), "roles.0" | "created.0" | "keys.0"))).cloned().collect();
        c.parts = parts;
        (!c.parts.is_empty()).then(|| (c.encode(), c))
    }).collect()
}

impl SyncEngine {
    /// The group label `l` belongs to as judged on connection `conn`: the group it is opened
    /// under there. Two connections may hold one label under different groups (a hint names it
    /// under its sender's thing at a host the sender names, spec/sync.md §3), so whatever came
    /// from a connection is judged by that connection's group alone. With no connection (or
    /// one not holding it): the group whose recorded `label.0` names it, else the group of a
    /// connection holding it (an open one first: a hint's thing may still be opening at a host
    /// its sender named), else the hint's thing.
    pub(crate) fn group_of(&mut self, l: &LabelId, conn: Option<ConnId>) -> Option<Tid> {
        if let Some(x) = conn.and_then(|c| self.lc(c, l)) {
            return Some(x.group);
        }
        if let Some((g, _)) = self.labels().into_iter().find(|(_, gl)| gl.id == *l) {
            return Some(g);
        }
        let on: Vec<&super::LConn> = self.conns.values().filter_map(|c| c.labels.get(l)).collect();
        if let Some(x) = on.iter().find(|x| x.phase == super::Phase::Open).or(on.first()) {
            return Some(x.group);
        }
        self.state.hints.get(l).map(|h| h.thing)
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
            Some(c) => super::memory::RelayFrom::Served(c),
            None => super::memory::RelayFrom::Host(conn.and_then(|c| self.conns.get(&c)).map(|c| c.host)),
        };
        let host: Option<HostKey> = conn.and_then(|c| self.conns.get(&c)).map(|c| c.host);
        let mut blobs = Vec::new();
        let mut memory_blobs = Vec::new();
        let mut touched = Vec::new();
        let mut fetch: Vec<BlobId> = Vec::new();
        let mut announced = false;
        // entries new here that no writer vouched for (a deposit, or a host's junk): no stamp
        // under the head's write key, or before a head is known any step's this node knows (a
        // host cannot make one; a superseded step's key may be a removed writer's)
        let mut unvouched = Vec::new();
        // the head's write key now (a Head event in the batch moves it)
        let head_write = |s: &Self| conn.and_then(|c| s.lc(c, &l)).and_then(|x| x.head.as_ref()).map(|h| h.keys.write);
        let first_write = head_write(self);
        let mut writers: Vec<VerifyingKey> = Vec::new();
        if first_write.is_none() && host.is_some() && events.iter().any(|e| matches!(e, LogEvent::Added { .. })) {
            writers = conn.and_then(|c| self.lc(c, &l)).map(|x| x.writers.clone()).unwrap_or_default();
            if let Some(g) = self.group_of(&l, conn)
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
            // an entry this node deleted or saw deleted, announced again within its tombstone
            // (a host an upload reached late, a stale push crossing the deletion, a peer echoing
            // an announcement): not fetched or served on, as a host's tombstone keeps the
            // identical blob out (spec/sync.md §5); a memory entry whose body is known is
            // recorded as present there quietly, so the pass deletes it there too
            if let LogEvent::Added { blob_id, wrap, .. } = &ev
                && self.state.tombs.contains_key(&(l, *blob_id))
            {
                if let Some(c) = conn.and_then(|c| self.conns.get_mut(&c)) {
                    c.req.fetching.remove(blob_id);
                }
                if let (Some(s), Some(kind)) = (host, self.state.tomb_kinds.get(&(l, *blob_id)).cloned()) {
                    if !self.state.entries.get(&(l, *blob_id)).is_some_and(|e| matches!(e.kind, Kind::Commit { .. })) {
                        self.state.set_entry_quiet(l, *blob_id, Entry { wrap: *wrap, stamp: None, cert: false, kind, memory: true });
                    }
                    self.state.set_present(s, l, *blob_id, true);
                    touched.push(*blob_id);
                }
                continue;
            }
            // a blob's prefix class routes it (spec/sync.md §9): a relay-only one is delivered
            // and passed on, held by nobody; an ephemeral one is a memory entry, recorded in
            // memory only, whatever an announcement without its bytes made the sync records hold
            let mut memory = false;
            if let LogEvent::Added { blob_id, blob: Some(blob), wrap, stamp } = &ev
                && let Ok(class) = osis_label::Prefix::parse(blob).map(|p| p.class())
                && class != osis_label::Class::Durable
            {
                if let Some(c) = conn.and_then(|c| self.conns.get_mut(&c)) {
                    c.req.missing.remove(blob_id);
                    c.req.fetching.remove(blob_id);
                }
                if class == osis_label::Class::Relay {
                    let head = conn.and_then(|c| self.lc(c, &l)).and_then(|x| x.head.as_ref()).map(|h| h.keys.write);
                    // a stamp counts if it verifies under the head's write key (a served peer's
                    // upload was checked by the host engine)
                    let stamp = stamp.filter(|s| head.as_ref().map_or(conn.is_none(), |w| osis_label::verify_stamp(w, &l, blob_id, wrap, s).is_ok()));
                    self.relay_in(from, l, *blob_id, blob.clone(), *wrap, stamp, out)?;
                    continue;
                }
                memory = true;
                if self.state.entries.get(&(l, *blob_id)).is_some_and(|e| !e.memory) {
                    self.state.forget_class(l, *blob_id);
                }
                if !self.state.entries.contains_key(&(l, *blob_id)) {
                    // recorded before its presence (`State::put_of` goes by the record's class)
                    self.state.set_entry(l, *blob_id, Entry { wrap: *wrap, stamp: None, cert: false, kind: Kind::Unknown, memory: true });
                }
            }
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
                    if let Some(s) = host {
                        self.state.set_present(s, l, blob_id, true);
                        self.state.set_deposited(s, l, blob_id, stamp.is_none());
                    }
                    // the host holds it now: fetched there again when wanted
                    if let Some(c) = conn.and_then(|c| self.conns.get_mut(&c)) {
                        c.req.missing.remove(&blob_id);
                    }
                    // what the host's entry is: one stamped under a superseded key never changes either
                    let held_stamped = stamp.is_some();
                    // a stamp counts only if it verifies under the head's write key (it is relayed);
                    // a bundle's stamps were checked against its path by the importer
                    let stamp = stamp.filter(|_| if cur.is_some() { by_head } else { conn.is_none() });
                    let listed = self.state.entries.contains_key(&(l, blob_id));
                    match self.state.entries.get(&(l, blob_id)).cloned() {
                        None => {
                            if host.is_some() && stamp.is_none() && !vouched {
                                // bytes held before (another label's entry) stay whatever happens
                                let fresh = blob.is_some() && !self.engine.has_blob(&blob_id);
                                unvouched.push((blob_id, fresh));
                            }
                            self.state.set_entry(l, blob_id, Entry { wrap, stamp, cert: false, kind: Kind::Unknown, memory: false })
                        }
                        Some(mut e) if e.wrap != wrap || (stamp.is_some() && e.stamp != stamp) => {
                            if self.take_wrap(conn, host, l, blob_id, &mut e, &wrap, stamp.is_some(), held_stamped) {
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
                        Some(b) if memory => {
                            self.fetched(&blob_id);
                            // a host's unstamped junk in the ephemeral class is judged as its
                            // durable junk is (`drop_unvouched`: opened under nothing, its bytes go)
                            if host.is_some() && !vouched && stamp.is_none() && !self.engine.has_blob(&blob_id) {
                                unvouched.push((blob_id, true));
                            }
                            memory_blobs.push((blob_id, b));
                        }
                        Some(b) => {
                            self.fetched(&blob_id);
                            // listed before its bytes: judged as they come (`drop_unvouched`)
                            if listed && host.is_some() && !vouched && stamp.is_none() && !self.engine.has_blob(&blob_id) {
                                unvouched.push((blob_id, true));
                            }
                            blobs.push((blob_id, b));
                        }
                        // nothing to open: only the entry changed (one refused for the node's
                        // ephemeral cap waits for room, `memory_skips`)
                        None if !self.engine.has_blob(&blob_id) && !self.memory_skips(&l, &blob_id) => {
                            fetch.push(blob_id);
                            announced = true;
                            continue;
                        }
                        None => {}
                    }
                    touched.push(blob_id);
                }
                LogEvent::Deleted(b) => {
                    self.memory_entry_gone(l, b);
                    // gone from every host of the label: a chunk an own commit may link
                    let chunk = !self.state.blobs.contains_key(&b);
                    if self.absent_at(host, l, b)? && chunk {
                        lost.insert(b);
                    }
                }
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
        let replaced = self.group_of(&l, conn).is_some_and(|g| self.is_replaced(&g, &l));
        if !lost.is_empty() && !replaced {
            self.relink_pending.extend(lost);
            self.relink_at = 0;
            self.relink_lost()?;
        }
        let filling = conn.is_some_and(|c| self.lc(c, &l).is_some_and(|x| x.fill.is_some()));
        // a push (no Sync running) brings the log to its end: a pass end
        let pushed = conn.and_then(|c| self.conns.get(&c)).and_then(|c| c.labels.get(&l)).is_some_and(|x| x.synced && !x.syncing && x.fill.is_none());
        // the label changed under us: a pass decides again (carriers, retags); not per batch of a fill
        if (!touched.is_empty() || announced)
            && !filling
            && let Some(lc) = conn.and_then(|c| self.conns.get_mut(&c)).and_then(|c| c.labels.get_mut(&l))
        {
            lc.dirty = true;
        }
        // bodies waiting for a linked blob upload it now it is here (`Left::links`)
        self.touched.blobs.extend(blobs.iter().map(|(b, _)| *b));
        // an entry these bytes make servable logs in their transaction, with its row
        if !blobs.is_empty() {
            self.state.flush_storing(&mut self.engine, blobs)?;
        }
        self.engine.put_memory_blobs(memory_blobs)?;
        self.open_entries(conn, l, &touched)?;
        // a cursor is stored only with what it covers applied: past `flush_storing` (a later
        // flush writes it) and the commits opened above
        if let (Some(s), Some(c)) = (host, cursor)
            && !conn.is_some_and(|x| self.fill_cursor(x, &l, c))
        {
            self.state.set_cursor(s, l, Some(c));
        }
        if let Some(s) = host {
            self.drop_unvouched(conn, s, l, &unvouched)?;
        }
        // commit blobs announced without bytes are fetched now; the rest (chunks) lazily
        if let Some(c) = conn {
            let g = self.group_of(&l, Some(c));
            let secrets = g.map(|g| self.read_secrets(&g)).unwrap_or_default();
            if filling {
                self.fill_add(c, l, &fetch);
                self.fetch_waiting(c, l, out)?;
                self.fill_more(c, l, out)?;
            } else {
                let want: Vec<BlobId> = fetch.into_iter().filter(|b| self.state.entries.get(&(l, *b)).is_some_and(|e| osis_label::unwrap_any(secrets.iter(), b, &e.wrap).is_some())).collect();
                self.fetch_on(c, l, want, out)?;
                self.fetch_waiting(c, l, out)?;
            }
        }
        if pushed && let Some(s) = host {
            self.bump_pass(s, l)?;
        }
        Ok(())
    }

    /// Whether another wrap `wrap` a source gave for held entry `e` replaces its wrap. Invariant
    /// (spec/sync.md §5): no wrap from anyone, a writer included, replaces one that opens to the
    /// blob's key, and a body stays readable through a host whose wrap is useless: a node knowing
    /// the key takes only a wrap opening to it and counts the host giving any other as lacking
    /// the entry (`State::holds_at`), so a writer uploads a fresh encryption there. Knowing
    /// no key, it prefers what opens; a wrap that opened to a wrong key (`Kind::Bad`) gives way.
    /// `stamped`: under the head's write key; `held_stamped`: the host holds it stamped under any
    /// (a hostile host saying so loses only its own entry here).
    #[allow(clippy::too_many_arguments)]
    fn take_wrap(&mut self, conn: Option<ConnId>, host: Option<HostKey>, l: LabelId, b: BlobId, e: &mut Entry, wrap: &[u8; osis_crypto::WRAP_LEN], stamped: bool, held_stamped: bool) -> bool {
        if e.wrap == *wrap {
            return true;
        }
        let secrets = self.group_of(&l, conn).map(|g| self.read_secrets(&g)).unwrap_or_default();
        let new = osis_label::unwrap_any(secrets.iter(), &b, wrap).map(|(_, k)| k);
        if let Some(k) = self.state.blobs.get(&b).map(|r| r.key.clone()) {
            let opens = new.as_ref().is_some_and(|x| x.expose() == k.expose());
            // a deposited one goes when a writer promotes it (with this wrap, if this node does)
            if let Some(s) = host.filter(|_| held_stamped) {
                match &new {
                    _ if opens => self.state.clear_gone(s, l, b),
                    Some(_) => self.state.set_gone(s, l, b),
                    None => self.state.set_doubtful(s, l, b, *wrap),
                }
            }
            return opens;
        }
        let opened = osis_label::unwrap_any(secrets.iter(), &b, &e.wrap).is_some();
        let bad = e.kind == Kind::Bad;
        // its wrap opens, the bytes are on their way, and this host's never will: heard only now
        if let Some(s) = host.filter(|_| held_stamped && opened && !bad && new.is_none()) {
            self.state.set_doubtful(s, l, b, *wrap);
        }
        let take = e.shredded() || (new.is_some() && (!opened || bad)) || (new.is_none() && !opened && stamped && e.stamp.is_none());
        if take && new.is_some() && !e.shredded() {
            // the wrap it replaces is useless at the hosts that gave it
            for s in self.state.hosts_of(&l, &b) {
                if Some(s) != host {
                    match opened {
                        true => self.state.set_gone(s, l, b),
                        false => self.state.set_doubtful(s, l, b, e.wrap),
                    }
                }
            }
        }
        if take && bad {
            e.kind = Kind::Unknown;
        }
        take
    }

    /// A wrap that opened under no read secret may be under an epoch this node lacks, and a node
    /// cannot tell garbage from that (spec/sync.md §5): once more secrets are held, one that opens
    /// to the blob's key was of use all along.
    pub(crate) fn recheck_doubts(&mut self) {
        let count = self.secrets_count();
        if self.state.doubts.is_empty() || self.state.doubts_at == count {
            return;
        }
        self.state.doubts_at = count;
        for ((s, l, b), wrap) in self.state.doubts.clone() {
            let secrets = self.group_of(&l, None).map(|g| self.read_secrets(&g)).unwrap_or_default();
            let Some((_, k)) = osis_label::unwrap_any(secrets.iter(), &b, &wrap) else { continue };
            let own = self.state.blobs.get(&b).map(|r| r.key.clone()).or_else(|| self.state.entries.get(&(l, b)).and_then(|e| osis_label::unwrap_any(secrets.iter(), &b, &e.wrap)).map(|(_, k)| k));
            match own {
                Some(o) if o.expose() == k.expose() => self.state.clear_gone(s, l, b),
                _ => self.state.drop_doubt(s, l, b),
            }
        }
    }

    /// New entries no writer vouched for that neither opened nor unwrap under a held read secret
    /// (a deposit under an epoch not held yet, an entry stamped under a step this node does not
    /// know, or a host's junk): their bytes are not kept (fetched again once they unwrap,
    /// `refetch`), and beyond `SyncConfig::unvouched_cap` such entries under the label at that
    /// host not even its presence there, nor the entry once no host has it
    /// (spec/requirements.md: peer input never causes unbounded storage; a dropped real entry
    /// comes back stamped once a writer promotes it, or with the next replay). Counted per host:
    /// one host's junk does not crowd out what others announce.
    ///
    /// Invariant (no fetch loop, whatever group a label is held under): bytes fetched on a
    /// connection are judged here under that connection's group (`group_of` with `conn`), the
    /// group every fetch on it was asked under (`log_events`' wanted entries, `refetch`'s
    /// `Work::unopened`): an entry fetched because it unwraps is kept, so it is never asked for
    /// again. Judged under another connection's group, the bytes would be dropped and asked for
    /// again at every pass.
    fn drop_unvouched(&mut self, conn: Option<ConnId>, host: HostKey, l: LabelId, ids: &[(BlobId, bool)]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let secrets = self.group_of(&l, conn).map(|g| self.read_secrets(&g)).unwrap_or_default();
        // pages and chunks a waiting commit lists (a reader's deposited commit) stay
        let mut listed = BTreeSet::new();
        for (c, r) in self.engine.pending() {
            if r == crate::Reason::WaitBlobs
                && let Some(h) = self.engine.commit_bytes(&c)?.and_then(|b| osis_commit::CommitBlob::decode_stored(&b).ok()).map(|cb| cb.header)
            {
                listed.extend(h.chunks.iter().map(|ch| ch.blob));
            }
        }
        // an inbox blob opens by its bytes (the read KEM key of an epoch learned later): kept,
        // under a smaller cap
        let inbox = !self.inbox_actors_at(&l).is_empty();
        let cap = if inbox { self.cfg.unvouched_cap >> 4 } else { self.cfg.unvouched_cap };
        let mut held = self.state.present_at(&host, &l).into_iter().filter(|b| self.state.entries.get(&(l, *b)).is_some_and(|e| e.kind == Kind::Unknown && e.stamp.is_none())).count();
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
                self.state.set_present(host, l, *b, false);
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

    /// The actors with held secrets whose `keys.0` names `l` as inbox (`Engine::inbox_actors`).
    pub(crate) fn inbox_actors_at(&mut self, l: &LabelId) -> Vec<Tid> {
        self.engine.inbox_actors().get(l).cloned().unwrap_or_default()
    }

    /// Opens entries of `l` not opened yet (from connection `conn`: under its group), ingests
    /// what they carry (role commits first), and retries every unopened entry while new secrets
    /// keep arriving.
    pub(crate) fn open_entries(&mut self, conn: Option<ConnId>, l: LabelId, ids: &[BlobId]) -> Result<()> {
        let mut todo: Vec<(LabelId, BlobId)> = ids.iter().map(|b| (l, *b)).collect();
        let start = self.secrets_count();
        let mut on = conn;
        for _ in 0..MAX_ROUNDS {
            let before = self.secrets_count();
            let mut commits: Vec<ToIngest> = Vec::new();
            for (l, b) in std::mem::take(&mut todo) {
                self.open_one(on, l, b, &mut commits)?;
            }
            // the retries are of every label's entries: each under its own group
            on = None;
            // creations first, then role commits by `ts` (spec/commits.md §4)
            commits.sort_by_key(|o| (!carries_creation(&o.commit), !o.commit.header.kind.is_role(), o.commit.header.ts));
            let mut unjudged: Vec<(ToIngest, crate::Reason)> = Vec::new();
            for o in commits {
                // a memory commit applies within the room the label's cap leaves (spec/sync.md §9)
                if o.commit.header.ephemeral.is_some() {
                    self.ingest_memory_entry(o.label, o.blob, o.size, &o.plaintext, &o.commit)?;
                    continue;
                }
                match self.engine.ingest(&o.plaintext, Vec::new()) {
                    Ok(Ingested::Awaits(_, r)) => unjudged.push((o, r)),
                    Ok(_) => {}
                    Err(e) => self.ingest_failed(&o.commit, e)?,
                }
            }
            self.settle_batch(unjudged)?;
            if self.secrets_count() == before {
                break;
            }
            todo = self.state.of_tag(Kind::TAG_UNKNOWN).into_iter().collect();
        }
        self.engine.reexamine()?;
        self.reread_boxes |= self.secrets_count() != start;
        self.recheck_doubts();
        self.vet_inbox_hints()
    }

    /// The batch `open_entries` opened: what awaits something the batch brought is judged again
    /// here, with its bytes; only what is still unjudgeable at the end is thrown out (`mark_awaits`),
    /// so a first sync's commits ahead of their records cost no second fetch. Bounded by `MAX_ROUNDS`
    /// a safety bound (past it the wake fetches them again).
    fn settle_batch(&mut self, mut unjudged: Vec<(ToIngest, crate::Reason)>) -> Result<()> {
        for _ in 0..MAX_ROUNDS {
            if unjudged.is_empty() {
                return Ok(());
            }
            let mut later = Vec::new();
            let mut progressed = false;
            for (o, r) in std::mem::take(&mut unjudged) {
                // what it awaits has not come: nothing to look at again
                if self.engine.core.created(&awaited(&r)).is_none() {
                    later.push((o, r));
                    continue;
                }
                match self.engine.ingest(&o.plaintext, Vec::new()) {
                    Ok(Ingested::Awaits(_, r)) => later.push((o, r)),
                    Ok(_) => progressed = true,
                    Err(e) => {
                        let _ = r;
                        progressed = true;
                        self.ingest_failed(&o.commit, e)?;
                    }
                }
            }
            unjudged = later;
            if !progressed {
                break;
            }
        }
        for (o, r) in unjudged {
            let Some(e) = self.state.entries.get(&(o.label, o.blob)) else { continue };
            // an inbox blob stays local: looked at again when what it awaits comes
            if matches!(e.kind, Kind::Inbox(Some(_))) {
                self.inbox_awaits.entry((o.label, o.blob)).or_default().insert(awaited(&r));
                continue;
            }
            // a label entry (never an inbox blob, whose bytes stay under its own budget) of a commit
            // still unapplied: applied, its waiting parts are the engine's (`Changed::undropped`)
            if matches!(e.kind, Kind::Commit { .. }) && !self.engine.core.ix.commits.contains_key(&o.commit.id()) {
                self.mark_awaits(o.label, o.blob, o.commit.id(), r)?;
            }
        }
        Ok(())
    }

    /// A commit refused: bad input drops what its earlier copies read of their boxes.
    fn ingest_failed(&mut self, c: &osis_commit::CommitBlob, e: crate::Error) -> Result<()> {
        if e.class() == ErrorClass::Local {
            return Err(e);
        }
        self.diag(format!("ingest {:?}: {e}", c.id()));
        if e.class() == ErrorClass::BadInput {
            self.engine.forget_awaiting(&c.id())?;
        }
        Ok(())
    }

    /// Entry `b` under `l` of commit `commit` cannot be judged: nothing of it is kept but what it
    /// awaits (notes/expiry-creation-design.md §3); the blob's bytes and key go, every label naming it alike.
    pub(crate) fn mark_awaits(&mut self, l: LabelId, b: BlobId, commit: CommitId, r: crate::Reason) -> Result<()> {
        let thing = awaited(&r);
        self.stats.awaits += 1;
        for x in self.state.labels_of(&b).into_iter().chain([l]) {
            if let Some(mut e) = self.state.entries.get(&(x, b)).cloned()
                && matches!(e.kind, Kind::Commit { .. })
            {
                e.kind = Kind::Awaits { commit, thing };
                self.state.set_entry(x, b, e);
            }
        }
        self.state.remove_blob(&b);
        self.delete_blobs(&[b])
    }

    /// Entries of what arrived are fetched again (notes/expiry-creation-design.md §3): those
    /// awaiting a record that came, reach waits on any move of edges (`Changed::moved`), commits
    /// the reading budget has room for now (`Changed::reread`). A waiting part of an applied
    /// commit comes by `Changed::undropped`.
    pub(crate) fn wake_awaiting(&mut self, w: &osis_engine::engine::Wakes) -> Result<()> {
        let mut ids: BTreeSet<(LabelId, BlobId)> = BTreeSet::new();
        if w.reopen_awaits {
            ids.extend(self.state.by_awaited.values().flatten().copied());
        }
        for t in &w.records {
            ids.extend(self.state.by_awaited.get(t).into_iter().flatten().copied());
        }
        if w.moved {
            let reach: Vec<Tid> = self.state.by_awaited.keys().filter(|t| self.engine.core.created(t).is_some()).copied().collect();
            for t in reach {
                ids.extend(self.state.by_awaited.get(&t).into_iter().flatten().copied());
            }
        }
        for c in &w.reread {
            ids.extend(self.state.awaits_by_commit.get(c).into_iter().flatten().copied());
        }
        self.reopen_awaiting(ids);
        // an inbox blob is opened again here, not fetched: it stays local under its own budget
        let core = &self.engine.core;
        let due = self.inbox_awaits.iter().filter(|(_, ts)| w.reopen_awaits || ts.iter().any(|t| w.records.contains(t) || (w.moved && core.created(t).is_some()))).map(|(k, _)| *k);
        self.retry_inbox.extend(due);
        if !w.reread.is_empty() {
            let reread: Vec<(LabelId, BlobId)> = self.state.of_tag(Kind::TAG_INBOX).into_iter().filter(|k| matches!(self.state.entries.get(k).map(|e| &e.kind), Some(Kind::Inbox(Some(c))) if w.reread.contains(c))).collect();
            self.retry_inbox.extend(reread);
        }
        Ok(())
    }

    fn reopen_awaiting(&mut self, ids: BTreeSet<(LabelId, BlobId)>) {
        // still awaited: it comes back judged or awaiting (`awaits_left` is for entries gone)
        let told = self.state.awaits_left.len();
        let mut labels = BTreeSet::new();
        for (l, b) in ids {
            if let Some(mut e) = self.state.entries.get(&(l, b)).cloned() {
                e.kind = Kind::Unknown;
                self.state.charge_memory(l, b, None);
                self.state.set_entry(l, b, e);
                labels.insert(l);
            }
        }
        self.state.awaits_left.truncate(told);
        if !labels.is_empty() {
            self.mark_labels(&labels);
        }
    }

    /// Every awaiting entry, fetched again at the start (a crash may have lost a wake; a refused
    /// box's turn is not remembered).
    pub(crate) fn reopen_all_awaiting(&mut self) {
        let ids = self.state.by_awaited.values().flatten().copied().collect();
        self.reopen_awaiting(ids);
        let inbox = self.state.of_tag(Kind::TAG_INBOX);
        self.retry_inbox.extend(inbox);
    }

    /// Ingests again the opened inbox blobs a wake named, chain first: their bytes stayed local
    /// (`INBOX_WAITING`).
    fn retry_inbox_commits(&mut self) -> Result<()> {
        let due = std::mem::take(&mut self.retry_inbox);
        if due.is_empty() {
            return Ok(());
        }
        for (l, b) in due {
            self.inbox_awaits.remove(&(l, b));
            let Some(Kind::Inbox(Some(c))) = self.state.entries.get(&(l, b)).map(|e| e.kind.clone()) else { continue };
            if self.state.declined.contains(&c) {
                continue;
            }
            let Some(bytes) = self.engine.blob(&b)? else { continue };
            let Some((_, payload)) = self.open_inbox(&l, &bytes) else { continue };
            let (pt, _, chain) = payload.split();
            // the author's chain first; what still cannot be judged is looked at again later
            for plain in chain_commits(chain).into_iter().map(|(plain, _)| plain).chain([pt]) {
                match self.engine.ingest(&plain, Vec::new()) {
                    Ok(Ingested::Awaits(_, r)) => {
                        self.inbox_awaits.entry((l, b)).or_default().insert(awaited(&r));
                    }
                    Ok(_) => {}
                    Err(e) => {
                        self.diag(format!("ingest {c:?} again: {e}"));
                        if e.class() == ErrorClass::BadInput {
                            self.engine.forget_awaiting(&c)?;
                        }
                    }
                }
                self.redelivered += 1;
            }
        }
        self.engine.reexamine()
    }

    /// Reading-only secrets and remembered headers whose source has no entry left go (`by_commit`
    /// empties, the last `Kind::Awaits` or inbox entry leaves: `forget_unchecked`, `no_entry_left`).
    fn sweep_unchecked(&mut self) -> Result<()> {
        let sources = self.engine.reading_sources();
        let awaiting = self.engine.awaiting_commits();
        if (sources.is_empty() && awaiting.is_empty()) || self.unchecked_swept == Some(self.state.version) {
            return Ok(());
        }
        self.unchecked_swept = Some(self.state.version);
        let held = |s: &Self, c: &CommitId| s.state.by_commit.contains_key(c) || s.state.awaits_by_commit.contains_key(c) || s.state.inbox_commits.contains_key(c);
        for c in sources {
            if !held(self, &c) {
                self.engine.forget_awaiting(&c)?;
            }
        }
        // what `awaits_on` remembers of headers seen is bounded by the entries holding them
        for c in awaiting {
            if !held(self, &c) {
                self.engine.no_entry_left(&c);
            }
        }
        Ok(())
    }

    /// Ingests again what the engine named: a pending commit's first copy of a slot or signature proved
    /// junk, so a true copy it kept out may be among the commit's other entries (spec/commits.md §4,
    /// `apply::with_pending`). Every commit bytes this node ingests are an entry whose blob it keeps
    /// (a label's, under `BlobRec.key`; an inbox's, opened again under its held keys), so nothing is
    /// stored for this, and a flood cannot keep a part out however large while the entries are there.
    /// Also after new secrets: the boxes of a commit's other copies (`with_pending`). A copy that is junk
    /// anywhere is no source: a true part in it also has its author's copy (a holder of the part who
    /// deletes that one can withhold it anyway).
    ///
    /// Invariant (no work without a junk copy stored): a name needs a stored copy proved junk, and a copy
    /// is stored only from an entry not judged false (a copy `examine` would drop anything of is
    /// `Some(false)` by `parts_genuine`, with the same inputs: marked `Kind::Bad`, not ingested again) on
    /// a slot left empty. So a commit's names run out, a true copy's slot goes to it, and in steady state
    /// this costs nothing. Should the invariant ever fail, a commit past one visit per entry waits for the
    /// next step rather than spin here: a bound on work, never on what is looked at.
    ///
    /// A copy brings no slot counting as never received (`Engine::settled_slots`: a body dropped for its
    /// keep bounds, a part past its expiry, spec/commits.md §5): such a slot comes back only as a new copy.
    pub(crate) fn redeliver(&mut self) -> Result<()> {
        // the node's epochs moved, by whatever path: a box or section of what awaits may open now
        // (spec/wire.md §4)
        let secrets = self.engine.core.secrets_moved;
        if secrets != std::mem::replace(&mut self.awaits_secrets, secrets) {
            let awaiting = self.state.by_awaited.values().flatten().copied().collect();
            self.reopen_awaiting(awaiting);
            let waiting: Vec<_> = self.inbox_awaits.keys().copied().collect();
            self.retry_inbox.extend(waiting);
        }
        self.retry_inbox_commits()?;
        for c in std::mem::take(&mut self.state.awaits_left) {
            if !self.state.awaits_by_commit.contains_key(&c) {
                self.engine.no_entry_left(&c);
            }
        }
        self.sweep_unchecked()?;
        if std::mem::take(&mut self.start_look) {
            self.name_after_crash();
        }
        let mut force: BTreeSet<CommitId> = if std::mem::take(&mut self.reread_boxes) {
            let mut f: BTreeSet<CommitId> = self.contested_boxes()?.into_iter().collect();
            // a section no secret opened may open under a secret learned since (spec/wire.md §4)
            f.extend(self.state.blobs.values().filter(|r| super::state::sealed(&r.ais, &r.parts)).map(|r| r.commit));
            f
        } else {
            BTreeSet::new()
        };

        let mut todo = self.engine.take_redeliver();
        todo.extend(force.iter().copied());
        if todo.is_empty() {
            return Ok(());
        }
        let before = self.secrets_count();
        let inbox = self.inbox_by_commit();
        let mut visits: BTreeMap<CommitId, usize> = BTreeMap::new();
        let mut later = Vec::new();
        while let Some(c) = todo.pop_first() {
            let forced = force.remove(&c);
            let entries: Vec<BlobId> = self.state.by_commit.get(&c).into_iter().flatten().copied().collect();
            let inbox = inbox.get(&c).map_or(&[][..], Vec::as_slice);
            let visit = visits.entry(c).or_default();
            *visit += 1;
            if *visit > 1 + entries.len() + inbox.len() {
                later.push(c);
                continue;
            }
            let mut held = self.engine.settled_slots(&c)?;
            for b in entries {
                let Some(r) = self.state.blobs.get(&b) else { continue };
                let (parts, key) = (r.parts.clone(), r.key.clone());
                // a junk copy is marked wherever it sorts among the commit's entries, also when
                // a true copy ingested before it already brought its slots
                self.genuine(&b);
                if self.genuine.get(&b) == Some(&false) {
                    continue;
                }
                if !forced && parts.iter().all(|p| held.contains(p)) {
                    continue;
                }
                let Some(bytes) = self.engine.blob(&b)? else { continue };
                let g = self.state.labels_of(&b).into_iter().find_map(|l| self.group_of(&l, None));
                let Ok(o) = self.engine.open_commit(&bytes, &key, g.as_ref()) else { continue };
                let opened = o.parts();
                if opened.len() > parts.len() {
                    self.state.note_opened(&b, &opened, o.copy);
                }
                self.ingest_again(&c, &o.plaintext);
                held.extend(opened);
            }
            for (l, b) in inbox {
                let Some(bytes) = self.engine.blob(b)? else { continue };
                let Some((_, payload)) = self.open_inbox(l, &bytes) else { continue };
                let (pt, ..) = payload.split();
                let Ok(blob) = osis_commit::CommitBlob::decode(&pt) else { continue };
                if (!forced && blob.parts.iter().all(|p| held.contains(&p.ai))) || self.engine.parts_genuine(&blob) == Some(false) {
                    continue;
                }
                self.ingest_again(&c, &pt);
                held.extend(blob.parts.iter().map(|p| p.ai));
            }
            self.engine.reexamine()?;
            todo.extend(self.engine.take_redeliver());
        }
        for c in later {
            self.engine.name_redeliver(c);
        }
        self.reread_boxes |= self.secrets_count() != before;
        // a copy kept for what a junk one held out of a pending commit may be spent now
        self.forget_dropped(Some(&visits.into_keys().collect()))
    }

    fn ingest_again(&mut self, c: &CommitId, plaintext: &[u8]) {
        self.redelivered += 1;
        if let Err(e) = self.engine.ingest(plaintext, Vec::new()) {
            self.diag(format!("ingest {c:?} again: {e}"));
        }
    }

    /// A crash may have lost what the engine named (`redeliver`). Looked at once per start: what pends,
    /// a commit with an entry that is neither applied nor pending (gone with a junk signature or all its
    /// junk), and an applied commit with an entry on an aspect it misses (a waiting part's junk slot
    /// gone). `redeliver` reads what it holds.
    fn name_after_crash(&mut self) {
        let ix = &self.engine.core.ix;
        let mut named: Vec<CommitId> = ix.pending.keys().copied().collect();
        named.extend(self.state.by_commit.iter().filter(|(c, blobs)| match ix.commits.get(c) {
            None => true,
            Some(m) => blobs.iter().filter_map(|b| self.state.blobs.get(b)).any(|r| r.parts.iter().any(|p| m.missing.contains(p))),
        }).map(|(c, _)| *c));
        for c in named {
            self.engine.name_redeliver(c);
        }
    }

    /// The inbox entries under the synced labels by the commit they carry, but for what the user declined.
    fn inbox_by_commit(&mut self) -> BTreeMap<CommitId, Vec<(LabelId, BlobId)>> {
        let labels: BTreeSet<LabelId> = self.labels().iter().map(|(_, x)| x.id).collect();
        let mut out: BTreeMap<CommitId, Vec<(LabelId, BlobId)>> = BTreeMap::new();
        for l in labels {
            for b in self.state.of_kind(&l, Kind::TAG_INBOX) {
                if let Some(Kind::Inbox(Some(c))) = self.state.entries.get(&(l, b)).map(|e| &e.kind)
                    && !self.state.declined.contains(c)
                {
                    out.entry(*c).or_default().push((l, b));
                }
            }
        }
        out
    }

    /// The pending role commits writing `secrets.0` with another entry than the one read: new secrets
    /// may open the boxes of a copy their first one kept out.
    fn contested_boxes(&mut self) -> Result<Vec<CommitId>> {
        let mut out = Vec::new();
        for (c, _) in self.engine.pending() {
            if self.state.by_commit.get(&c).map_or(0, BTreeSet::len) < 2 {
                continue;
            }
            let Some(h) = self.engine.commit_bytes(&c)?.and_then(|b| osis_commit::CommitBlob::decode_stored(&b).ok()).map(|b| b.header) else { continue };
            if h.kind.is_role() && h.aspects.iter().any(|a| a.ak.as_str() == "secrets.0") {
                out.push(c);
            }
        }
        Ok(out)
    }

    pub(crate) fn secrets_count(&self) -> usize {
        let count = || self.engine.core.ix.secrets.values().map(|e| e.read.secret_count() + e.write.secret_count() + e.admin.secret_count()).sum();
        // secrets move only with the engine
        let at = (self.engine.core.generation, self.engine.core.memory_generation);
        match self.secrets_counted.get() {
            Some((k, n)) if k == at => {
                debug_assert_eq!(n, count(), "secrets_count cached");
                n
            }
            _ => {
                let n = count();
                self.secrets_counted.set(Some((at, n)));
                n
            }
        }
    }

    fn open_one(&mut self, conn: Option<ConnId>, l: LabelId, b: BlobId, commits: &mut Vec<ToIngest>) -> Result<()> {
        let Some(mut e) = self.state.entries.get(&(l, b)).cloned() else { return Ok(()) };
        if e.kind != Kind::Unknown {
            return Ok(());
        }
        let Some(bytes) = self.engine.blob(&b)? else { return Ok(()) };
        let Some(g) = self.group_of(&l, conn) else { return Ok(()) };
        let secrets = self.read_secrets(&g);
        if let Some((_, key)) = osis_label::unwrap_any(secrets.iter(), &b, &e.wrap) {
            // this group's closure is synced (spec/sync.md §3) from the first entry it opens: a
            // label named by another's word, with no entry readable, asks for nothing
            if !self.engine.core.ix.syncing.contains(&g) {
                self.engine.set_syncing(g, true)?;
            }
            match self.engine.open_commit(&bytes, &key, Some(&g)) {
                Ok(o) => {
                    let parts = o.parts();
                    let commit = o.commit.id();
                    if !self.state.blobs.contains_key(&b) {
                        self.state.add_blob(b, BlobRec { commit, parts: parts.clone(), ais: o.ais.clone(), key, cert: e.cert || o.copy, memory: e.memory });
                    }
                    let salt = osis_label::Prefix::parse(&bytes).map(|p| *p.salt()).unwrap_or_default();
                    e.kind = Kind::Commit { commit, parts, ais: o.ais, salt };
                    self.state.set_entry(l, b, e);
                    self.state.note_memory_size(l, b, bytes.len());
                    commits.push(ToIngest { label: l, blob: b, size: bytes.len(), plaintext: o.plaintext, commit: o.commit });
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
        let Some((actor, prefix, payload)) = self.open_inbox_as(&l, &bytes) else { return Ok(()) };
        let (pt, things, chain) = payload.split();
        let c = osis_commit::CommitBlob::decode(&pt).ok();
        let o = c.as_ref().map(|c| Opened::new(&prefix, c, things.clone()));
        // its labels are followed only once vetted (`vet_inbox_hints`)
        self.inbox_opened.insert((l, b), o.clone().map(Arc::new));
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
            self.engine.note_delete_hints(id, &things)?;
            e.kind = Kind::Inbox(Some(id));
            // the author's chain first (spec/wire.md §9): the commit applies with no label of the
            // thing read
            commits.extend(chain_commits(chain).into_iter().map(|(plaintext, commit)| ToIngest { label: l, blob: b, size: 0, plaintext, commit }));
            commits.push(ToIngest { label: l, blob: b, size: 0, plaintext: pt, commit: c });
            // the pass of the inbox's label stamps it, the home label's of the actor it is sealed
            // to or one above it places its copy (`inbox_certificates`); applying starts them only
            // if the commit is new here, and a sender's own deposit under its own inbox is not
            let scope: BTreeSet<Tid> = self.engine.record_chain(&actor).collect();
            self.mark_dirty_of(&scope);
            self.mark_labels(&[l]);
        }
        self.state.set_entry(l, b, e);
        Ok(())
    }

    /// Whether an opened inbox blob carrying commit `c` is admitted (spec/sync.md §3, invite
    /// requests): `c` is held (from a label this node syncs: a sibling node accepted it and
    /// placed its copy), or its sender is connected. `roots` caches what a sender must have a
    /// role on within one judging round.
    fn admits(&mut self, c: &CommitId, o: &Opened, roots: &mut Option<BTreeSet<Tid>>) -> bool {
        // held from a label this node syncs: applied, or an entry of it awaits or pends
        if self.engine.core.ix.commits.contains_key(c) || self.engine.core.ix.pending.contains_key(c) || self.state.awaits_by_commit.contains_key(c) {
            return true;
        }
        // the author's node, then the actors it is named on as a holder, transitively (held
        // edges, past and invalid ones too: candidates only, its current role decides below)
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
                    r.extend(self.engine.record_chain(&g));
                }
                roots.insert(r)
            }
        };
        // a current role: an ex-holder (a removed node, a kicked holder) is a stranger again
        let core = &self.engine.core;
        if !up.intersection(roots).any(|r| *r == o.author || core.role_now(&o.author, r).is_some()) {
            return false;
        }
        // a connected author's signature at its epoch: a stranger may name any author
        osis_engine::apply::signed_at(&self.engine.core, c, &o.author, o.epoch, &o.sigs)
    }

    /// The request entries under the synced labels: (label, blob, commit).
    fn request_entries(&mut self) -> Vec<(LabelId, BlobId, CommitId)> {
        self.labels();
        self.state
            .of_tag(Kind::TAG_REQUEST)
            .into_iter()
            .filter(|(l, _)| self.synced.ids.contains(l))
            .filter_map(|(l, b)| match self.state.entries.get(&(l, b)).map(|e| &e.kind) {
                Some(Kind::Request(c)) => Some((l, b, *c)),
                _ => None,
            })
            .collect()
    }

    /// The invite requests waiting for the user (spec/sync.md §3), by commit, unexpired.
    pub fn invite_requests(&mut self) -> Result<Vec<CommitId>> {
        let now = self.now();
        let mut out = BTreeSet::new();
        for (l, b, c) in self.request_entries() {
            if self.inbox_opened(&l, &b)?.is_some_and(|o| o.until > now) {
                out.insert(c);
            }
        }
        Ok(out.into_iter().collect())
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
            let (pt, things, chain) = payload.split();
            let Ok(blob) = osis_commit::CommitBlob::decode(&pt) else { continue };
            if let Some(mut e) = self.state.entries.get(&(l, b)).cloned() {
                e.kind = Kind::Inbox(Some(x));
                self.state.set_entry(l, b, e);
            }
            self.engine.note_delete_hints(x, &things)?;
            for (cpt, cb) in chain_commits(chain) {
                if let Err(e) = self.engine.ingest(&cpt, Vec::new()) {
                    self.diag(format!("ingest {:?}: {e}", cb.id()));
                }
            }
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

    /// Opens inbox blob `bytes` under the held keys of an actor whose inbox `l` is. A blob whose
    /// prefix no inbox blob has (an expiry, no commitments: spec/wire.md §9) costs no KEM: a group's
    /// home label is its inbox too, with every chunk of its content under it.
    fn open_inbox(&mut self, l: &LabelId, bytes: &[u8]) -> Option<(osis_label::Prefix, osis_label::InboxPayload)> {
        self.open_inbox_as(l, bytes).map(|x| (x.1, x.2))
    }

    /// `open_inbox`, with the actor it is sealed to.
    fn open_inbox_as(&mut self, l: &LabelId, bytes: &[u8]) -> Option<(Tid, osis_label::Prefix, osis_label::InboxPayload)> {
        let p = osis_label::Prefix::parse(bytes).ok()?;
        if p.expiry().is_none() || !p.groups().is_empty() {
            return None;
        }
        self.stats.inbox_tries += 1;
        // a KEM per try, so one at a time
        for a in self.inbox_actors_at(l) {
            for s in self.read_secrets(&a) {
                self.stats.inbox_keys += 1;
                if let Ok((p, x)) = osis_label::open_inbox_blob(bytes, &a, &role_kem(&s)) {
                    return Some((a, p, x));
                }
            }
        }
        None
    }

    /// What opened inbox blob `b` under `l` carries (cached; it opens again under the held keys
    /// of an actor whose inbox `l` is), if its bytes are held and its commit decodes.
    pub(crate) fn inbox_opened(&mut self, l: &LabelId, b: &BlobId) -> Result<Option<Arc<Opened>>> {
        if let Some(x) = self.inbox_opened.get(&(*l, *b)) {
            return Ok(x.clone());
        }
        let Some(bytes) = self.engine.blob(b)? else { return Ok(None) };
        // one that no longer opens is not tried again (a KEM per try)
        let Some((prefix, payload)) = self.open_inbox(l, &bytes) else {
            self.inbox_opened.insert((*l, *b), None);
            return Ok(None);
        };
        let (pt, things, _) = payload.split();
        let x = osis_commit::CommitBlob::decode(&pt).ok().map(|c| Arc::new(Opened::new(&prefix, &c, things)));
        self.inbox_opened.insert((*l, *b), x.clone());
        Ok(x)
    }

    /// The aspect indexes of the commit inbox blob `b` under `l` carries and the things it
    /// names, if its bytes are held.
    pub(crate) fn inbox_parts(&mut self, l: &LabelId, b: &BlobId) -> Result<Option<(BTreeSet<usize>, Vec<Tid>)>> {
        Ok(self.inbox_opened(l, b)?.map(|o| (o.ais.clone(), o.things.iter().map(|t| t.tid).collect())))
    }

    /// Whether the `label.0` of a group here records `l`.
    fn recorded(&mut self, l: &LabelId) -> bool {
        self.engine.labeled_groups().iter().any(|g| self.engine.labels_of(g).iter().any(|x| x.id == *l))
    }

    /// Follows the labels opened inbox blobs name (spec/sync.md §3) as hints, from scratch: per
    /// unexpired blob whose commit is applied or pending, the first payload thing with no known
    /// label that the commit gave this node a read secret of (`Engine::boxed_by`), one per blob
    /// (a delivery names one thing), so the hints a stranger makes are bounded by the inbox's
    /// deposit budget and go with the blob (a connected sender's stamped ones: by what the host
    /// takes, notes/inbox.md Invite requests). The payload is the sender's word: hosts only, never
    /// a node to dial (`peer://`); a label a key actor's entry is followed for (`via`) is left
    /// to that follow. A label a group here records is that group's, whether synced now or not:
    /// never a hint (it would take the label's place on the connection under the wrong thing's
    /// secrets). Blobs naming one label under different things are tried in turn (`hint_failed`:
    /// the first thing that has not failed since the last retry) at the hosts all of them name,
    /// so no sender's word holds a label from the thing it belongs to: a wrong thing fails at the
    /// label's real host. Other inbox hints are dropped.
    pub(crate) fn vet_inbox_hints(&mut self) -> Result<()> {
        // nothing it reads moved: the engine, the entries or the clock past an expiry
        let (generation, version, now) = (self.engine.core.generation, self.state.version, self.now());
        let quiet = self.vetted.is_some_and(|(g, v, at)| g == generation && v == version && now < at);
        // debug builds compare the skipped run with a real one, once per point of the store
        #[cfg(debug_assertions)]
        let check = quiet && self.engine.recheck(format!("vet_inbox_hints {version}"));
        #[cfg(not(debug_assertions))]
        let check = false;
        if quiet && !check {
            return Ok(());
        }
        #[cfg(debug_assertions)]
        let before = check.then(|| self.state.hints.iter().map(|(l, h)| (*l, format!("{h:?}"))).collect::<Vec<_>>());
        let (expires, released) = self.vet_inbox_hints_now()?;
        #[cfg(debug_assertions)]
        if let Some(b) = before {
            assert!(!released, "vet_inbox_hints skipped a request");
            assert_eq!(b, self.state.hints.iter().map(|(l, h)| (*l, format!("{h:?}"))).collect::<Vec<_>>(), "vet_inbox_hints skipped");
        }
        let _ = released;
        // what it did (a released request, hints written) is its own change: a second run settles
        self.vetted = Some((generation, version, expires));
        Ok(())
    }

    /// `vet_inbox_hints` itself. When the first inbox blob it counted expires, and whether it
    /// released a request.
    fn vet_inbox_hints_now(&mut self) -> Result<(u64, bool)> {
        self.stats.vets += 1;
        // requests admitted since (the sender became connected, a sibling node accepted)
        let released = self.release_requests(None)?;
        if released {
            self.engine.reexamine()?;
        }
        let now = self.now();
        // the synced labels' inbox entries (runs per `run_dirty`: never a scan of every entry)
        self.labels();
        let inbox: Vec<(LabelId, BlobId, Option<CommitId>)> = self
            .state
            .of_tag(Kind::TAG_INBOX)
            .into_iter()
            .filter(|(l, _)| self.synced.ids.contains(l))
            .filter_map(|(l, b)| match self.state.entries.get(&(l, b)).map(|e| &e.kind) {
                Some(Kind::Inbox(c)) => Some((l, b, *c)),
                _ => None,
            })
            .collect();
        // a request waiting for the user keeps its opened payload too: a KEM per vet otherwise
        let mut live: BTreeSet<(LabelId, BlobId)> = inbox.iter().map(|(l, b, _)| (*l, *b)).collect();
        live.extend(self.state.of_tag(Kind::TAG_REQUEST));
        self.inbox_opened.retain(|k, _| live.contains(k));
        let mut want: BTreeMap<LabelId, Hint> = BTreeMap::new();
        let mut expires = u64::MAX;
        for (l, b, c) in inbox {
            let Some(c) = c else { continue };
            // applied, or an entry held; a refused commit's reading-only secrets went (`boxed_by`)
            let Some(o) = self.inbox_opened(&l, &b)? else { continue };
            if o.until <= now {
                continue;
            }
            expires = expires.min(o.until);
            for t in &o.things {
                let Some(at) = &t.label else { continue };
                if !self.engine.labels_of(&t.tid).is_empty() || !self.engine.boxed_by(&c, &t.tid) || self.recorded(&at.id) {
                    continue;
                }
                let hosts = at.hosts.iter().filter(|a| !super::peers::is_peer(a)).cloned();
                let src = super::state::InboxSource { label: l, blob: b, until: o.until };
                match want.get_mut(&at.id) {
                    // two blobs naming one label: both hosts; of one thing the later expiry, of
                    // another its turn once this one failed
                    Some(h) => {
                        for a in hosts {
                            if !h.hosts.contains(&a) {
                                h.hosts.push(a);
                            }
                        }
                        let failed = |thing, index| self.hint_failed.contains(&(at.id, thing, index));
                        if (h.thing, h.index) == (t.tid, at.index) {
                            if h.inbox.is_some_and(|i| i.until < o.until) {
                                h.inbox = Some(src);
                            }
                        } else if failed(h.thing, h.index) && !failed(t.tid, at.index) {
                            (h.thing, h.index, h.inbox) = (t.tid, at.index, Some(src));
                        }
                    }
                    None => {
                        want.insert(at.id, Hint { thing: t.tid, index: at.index, hosts: hosts.collect(), via: None, inbox: Some(src) });
                    }
                }
                break;
            }
        }
        let gone: Vec<LabelId> = self.state.hints.iter().filter(|(l, h)| h.via.is_none() && !want.contains_key(l)).map(|(l, _)| *l).collect();
        for l in gone {
            self.state.remove_hint(&l);
        }
        // turns of labels no blob still names are over
        self.hint_failed.retain(|x| want.contains_key(&x.0));
        for (l, h) in want {
            let old = self.state.hints.get(&l);
            if old.is_some_and(|x| x.via.is_some() || (x.thing, x.index, &x.hosts, x.inbox) == (h.thing, h.index, &h.hosts, h.inbox)) {
                continue;
            }
            self.state.add_hint(l, h);
        }
        Ok((expires, released))
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
            let (pt, named, _) = payload.split();
            let names = named.iter().any(|t| things.contains(&t.tid)) || osis_commit::CommitBlob::decode(&pt).is_ok_and(|c| c.header.aspects.iter().any(|a| things.contains(&a.tid)));
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

    /// A new head in a host's log: a child of the current one moves on, and reopens when its
    /// sync key is another (the host ended the open, spec/sync.md §5); anything else reopens.
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

    /// A Sync ran through its last page: the pass at this host is complete.
    pub(crate) fn synced(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(host) = self.conns.get(&conn).map(|c| c.host) else { return Ok(()) };
        // a fill's pass ends with the fill
        if self.fill_listed(conn, l, out)? {
            return self.fetch_waiting(conn, l, out);
        }
        if let Some(lc) = self.lc_mut(conn, &l) {
            lc.syncing = false;
            lc.synced = true;
            lc.dirty = true;
        }
        self.bump_pass(host, l)?;
        self.fetch_waiting(conn, l, out)
    }

    pub(crate) fn bump_pass(&mut self, host: HostKey, l: LabelId) -> Result<()> {
        // role commits applied by this run count before the pass end
        self.engine_events()?;
        self.seq += 1;
        self.state.note_passed(l);
        self.passes.insert((host, l), (self.seq, self.now()));
        Ok(())
    }

    /// Commits wait for pages: fetch the blobs their headers list that are not held (pages
    /// before apply, spec/sync.md §6; the chunks of other large values stay lazy).
    fn fetch_waiting(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<super::Action>) -> Result<()> {
        let waiting: Vec<osis_base::CommitId> = self.engine.pending().into_iter().filter(|(_, r)| *r == crate::Reason::WaitBlobs).map(|(c, _)| c).collect();
        let mut missing = BTreeSet::new();
        for c in waiting {
            let Some(bytes) = self.engine.commit_bytes(&c)? else { continue };
            let Ok(cb) = osis_commit::CommitBlob::decode_stored(&bytes) else { continue };
            // asked of the label whether or not an entry was seen (an unstamped one that opened
            // under nothing is not kept, `drop_unvouched`)
            missing.extend(cb.header.chunks.iter().map(|ch| ch.blob).filter(|b| !self.engine.has_blob(b)));
        }
        self.fetch_on(conn, l, missing, out)
    }

    /// Fetches `ids` under `l` on `conn`, but those asked for already (on any connection) and
    /// those its host did not deliver (since it last announced them). Every fetch goes this
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

    /// Entry `b` under `l` is no longer at `host`: once no host holds it, the entry goes
    /// (tombstoned) with the blob's record and bytes where nothing else needs them. Whether it
    /// went.
    pub(crate) fn absent_at(&mut self, host: Option<HostKey>, l: LabelId, b: BlobId) -> Result<bool> {
        if let Some(s) = host {
            self.state.set_present(s, l, b, false);
        }
        // an upload of it unanswered elsewhere: the entry is kept until that host answers, so a
        // body forgotten meanwhile is deleted there too (`entry_status`, `memory_lost`)
        if self.state.present_anywhere(&l, &b) || self.upload_in_flight(&l, &b) {
            return Ok(false);
        }
        self.state.remove_entry(l, b);
        self.forget_blob(&b)?;
        self.forget_chunk(&b)?;
        Ok(true)
    }

    /// Drops a commit blob no label entry names any more whose deltas are not all held (its
    /// key and ciphertext: a dropped body's copies go, spec/commits.md §5). A pending commit's true copy
    /// goes so too, a junk copy perhaps holding its slot (`redeliver` then finds nothing): keeping it
    /// would store what a sender floods and deletes, and the deletion is what a body's holders repair
    /// by uploading it again.
    pub(crate) fn forget_blob(&mut self, b: &BlobId) -> Result<()> {
        let Some(r) = self.state.blobs.get(b).cloned() else { return Ok(()) };
        let unused = !self.state.named(b);
        if unused && (r.cert || !self.engine.core.ix.commits.contains_key(&r.commit)) || self.dropped(b, &r)? {
            self.drop_blob(b)?;
        }
        Ok(())
    }

    /// Forgets commit blob `b`'s key and ciphertext; its entries stay (deletes at hosts need no
    /// copy) with their wraps shredded.
    fn drop_blob(&mut self, b: &BlobId) -> Result<()> {
        let ls: Vec<LabelId> = self.state.labels_of(b);
        for l in ls {
            if let Some(mut e) = self.state.entries.get(&(l, *b)).cloned() {
                e.wrap = [0; osis_crypto::WRAP_LEN];
                e.stamp = None;
                self.state.set_entry(l, *b, e);
            }
        }
        self.state.remove_blob(b);
        self.delete_blobs(&[*b])
    }

    /// Whether commit blob `b` (`r`) holds a delta that went from the node (spec/commits.md §5): one
    /// the engine dropped of an applied commit, or for a commit held pending one past its expiry or
    /// purged, the blob holding nothing a redelivery may need (`Engine::spent_copy`: judged only
    /// where parts of the commit wait or it is named for redelivery).
    fn dropped(&mut self, b: &BlobId, r: &BlobRec) -> Result<bool> {
        let pending = self.engine.core.ix.pending.contains_key(&r.commit);
        if let Some(m) = self.engine.core.ix.commits.get(&r.commit) {
            if !r.parts.iter().any(|p| m.body_gone(*p)) {
                return Ok(false);
            }
            if !pending && !self.engine.redeliver_named(&r.commit) {
                return Ok(true);
            }
        } else if !pending {
            return Ok(false);
        }
        // a copy not held here holds nothing a redelivery could read
        let applied = self.engine.core.ix.commits.contains_key(&r.commit);
        let Some(bytes) = self.engine.blob(b)? else { return Ok(applied) };
        let g = self.state.labels_of(b).into_iter().find_map(|l| self.group_of(&l, None));
        let Ok(o) = self.engine.open_commit(&bytes, &r.key, g.as_ref()) else { return Ok(applied) };
        self.engine.spent_copy(&r.commit, &o.commit)
    }

    /// The entries of commits with a part missing again (`Changed::undropped`: dropped under a
    /// cover that no longer carries it, spec/permissions.md §5.2, held value-less for a purge
    /// that fell, or dropped while invalid and valid since, §6): unopened again, so a pass fetches
    /// them where present (`refetch`), the reply bringing the wrap back. Bytes still held (the
    /// drop and its undoing in one step, before `forget_dropped`) go first: the fetch is the one
    /// way back. A body deleted everywhere comes back only as a holder's new upload. `None`:
    /// every commit (at start: a crash may have come between the engine's change and this).
    pub(crate) fn reopen_undropped(&mut self, commits: Option<&BTreeSet<osis_base::CommitId>>) -> Result<()> {
        if commits.is_some_and(BTreeSet::is_empty) {
            return Ok(());
        }
        let ix = &self.engine.core.ix;
        let again = |c: &osis_base::CommitId, parts: &[usize]| commits.is_none_or(|cs| cs.contains(c)) && ix.commits.get(c).is_some_and(|m| parts.iter().any(|p| m.missing.contains(p)));
        // at start, bytes still held are a part waiting or one the engine has not taken yet
        let ids: Vec<(LabelId, BlobId)> = match commits {
            Some(cs) => cs.iter().flat_map(|c| self.entries_of_commit(c)).filter(|k| matches!(self.state.entries.get(k).map(|e| &e.kind), Some(Kind::Commit { commit, parts, .. }) if again(commit, parts))).collect(),
            None => self.state.entries.iter().filter(|((_, b), e)| !self.state.blobs.contains_key(b) && matches!(&e.kind, Kind::Commit { commit, parts, .. } if again(commit, parts))).map(|(k, _)| *k).collect(),
        };
        for (l, b) in ids {
            if self.state.blobs.contains_key(&b) {
                self.drop_blob(&b)?;
            }
            if let Some(mut e) = self.state.entries.get(&(l, b)).cloned() {
                e.kind = Kind::Unknown;
                self.state.set_entry(l, b, e);
            }
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
        self.delete_blobs(&[*b])
    }

    /// Forgets every commit blob holding a delta the engine dropped (purge, expiry, keep at
    /// most, compaction): key and ciphertext (spec/commits.md §5). Only those of `commits`
    /// when given (the commits a change may have dropped deltas of).
    pub(crate) fn forget_dropped(&mut self, commits: Option<&BTreeSet<osis_base::CommitId>>) -> Result<()> {
        let fresh = std::mem::take(&mut self.state.new_blobs);
        let commits: Option<BTreeSet<osis_base::CommitId>> = commits.map(|c| c.union(&fresh).copied().collect());
        let commits = commits.as_ref();
        let ids: Vec<BlobId> = match commits {
            None => self.state.blobs.keys().copied().collect(),
            Some(cs) => cs.iter().flat_map(|c| self.state.by_commit.get(c).into_iter().flatten()).copied().collect(),
        };
        for id in ids {
            let Some(r) = self.state.blobs.get(&id).cloned() else { continue };
            if self.dropped(&id, &r)? {
                self.drop_blob(&id)?;
            }
        }
        // chunks of dropped deltas no label entry names (never uploaded, or deleted everywhere)
        let listed: BTreeSet<BlobId> = match commits {
            None => self.engine.core.ix.commits.values().filter(|m| !m.dropped.is_empty() || !m.stripped.is_empty()).flat_map(|m| m.view.chunks.iter().copied()).collect(),
            Some(cs) => cs.iter().filter_map(|c| self.engine.core.ix.commits.get(c)).filter(|m| !m.dropped.is_empty() || !m.stripped.is_empty()).flat_map(|m| m.view.chunks.iter().copied()).collect(),
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
                let v: Vec<BlobId> = ids.iter().filter(|b| self.state.is_present(&c.host, l, b)).copied().collect();
                if !v.is_empty() {
                    todo.push((*conn, *l, v));
                }
            }
        }
        // each blob from the first connection whose host may deliver it (`fetch_on` skips
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

    /// Fetches every entry not held yet from the hosts holding it (lazy chunks, on demand).
    pub fn fetch_missing(&mut self) -> Vec<super::Action> {
        let ids: Vec<BlobId> = self.state.entries.iter().filter(|(_, e)| e.kind == Kind::Unknown).map(|((_, b), _)| *b).collect();
        let ids: Vec<BlobId> = ids.into_iter().filter(|b| !self.engine.has_blob(b)).collect();
        self.fetch(&ids)
    }

    /// Gained IDs the host lacks: upload the stamped entries held.
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
    /// metadata Sync for a fresh cursor. After a trimmed log (code 15) an entry known present
    /// there and absent now was deleted there, as by a Deleted record (`absent_at`); after
    /// another log (a wiped host) it is only not present.
    pub(crate) fn reconciled(&mut self, conn: ConnId, l: LabelId, need: Vec<BlobId>, have: Vec<BlobId>, out: &mut Vec<super::Action>) -> Result<()> {
        let Some((host, trimmed)) = self.conns.get_mut(&conn).map(|c| (c.host, c.req.trimmed.remove(&l))) else { return Ok(()) };
        // a reconciliation after a start keeps the cursor: the Sync from it that follows settles
        // the durable entries (Deleted records, or code 10 or 15 and a reconciliation again)
        let restart = self.memory.reconciling.contains(&(conn, l));
        let mut lost = BTreeSet::new();
        for b in have {
            if trimmed && self.state.is_present(&host, &l, &b) {
                // as a Deleted record: a chunk gone from every host is relinked (`log_events`)
                let chunk = !self.state.blobs.contains_key(&b);
                if self.absent_at(Some(host), l, b)? && chunk {
                    lost.insert(b);
                }
            } else if !restart {
                self.state.set_present(host, l, b, false);
            }
        }
        if !lost.is_empty() && !self.group_of(&l, Some(conn)).is_some_and(|g| self.is_replaced(&g, &l)) {
            self.relink_pending.extend(lost);
            self.relink_at = 0;
            self.relink_lost()?;
        }
        // the host holds them now: undelivered before or not, asked again (like an announce)
        if let Some(c) = self.conns.get_mut(&conn) {
            for b in &need {
                c.req.missing.remove(b);
            }
        }
        let need: Vec<BlobId> = need.into_iter().filter(|b| !self.memory_skips(&l, b)).collect();
        if restart {
            self.memory.reconcile_fetches.insert((conn, l), need.iter().copied().collect());
        }
        self.fetch_on(conn, l, need, out)?;
        // a reconciliation after a start: the cursor stays (`sync_label`)
        if self.memory.reconciling.remove(&(conn, l)) {
            self.memory.reconciled.insert((host, l));
            return self.sync_label(conn, l, out);
        }
        if let Some(lc) = self.lc_mut(conn, &l) {
            lc.syncing = true;
        }
        self.command(conn, Command::Sync { label: l, cursor: None, inline_limit: 0, entries: Vec::new(), gained: Vec::new() }, out)
    }

    /// Whether an upload of entry `b` of `l` is unanswered on any connection.
    pub(crate) fn upload_in_flight(&self, l: &LabelId, b: &BlobId) -> bool {
        self.conns.values().any(|c| c.req.sent.contains_key(&(*l, *b)) || c.req.replacing.contains_key(&(*l, *b)))
    }

    /// Upload or Sync statuses. Code 9 (signed under a key older than the head's) needs nothing
    /// here: the node uploads only where the label is open, so the new head comes by push or
    /// the next Sync (spec/sync.md §5), and its pass signs again under the new keys.
    pub(crate) fn entry_status(&mut self, conn: ConnId, l: LabelId, ids: Vec<BlobId>, codes: Vec<Code>) -> Result<()> {
        let Some(host) = self.conns.get(&conn).map(|c| c.host) else { return Ok(()) };
        let mut grew = false;
        for (b, code) in ids.into_iter().zip(codes) {
            // an own memory upload taken: the label's own writes held back go (`coalesce_own`)
            if self.memory.own_uploads.remove(&(conn, l, b)) && code == Code::OK {
                grew = true;
            }
            // a relay-only upload: nothing is held of it
            if self.relay_status(&b, code) {
                continue;
            }
            let replaced = self.conns.get_mut(&conn).and_then(|c| {
                c.req.sent.remove(&(l, b));
                c.req.replacing.remove(&(l, b))
            });
            // a memory entry refused for the host's cap or rate waits its resend time, as if in
            // flight, before a pass sends it again: room appears by others' expiries and
            // compactions, not by asking again at once (one refused under an older head, code 9,
            // goes again as soon as the new head is known, as a durable one); one no host holds
            // and nothing more is uploading goes (it waited for this answer)
            if code != Code::OK && self.state.is_memory(&l, &b) {
                // kept only for this upload: a body forgotten meanwhile, held nowhere
                let dead = matches!(self.state.entries.get(&(l, b)), Some(Entry { kind: Kind::Commit { commit, .. }, .. }) if !self.engine.holds_memory(commit));
                if dead && !self.state.present_anywhere(&l, &b) && !self.upload_in_flight(&l, &b) {
                    self.absent_at(None, l, b)?;
                } else if matches!(code, Code::STORAGE_CAP | Code::RATE_LIMITED) {
                    let raw = self.raw_now();
                    if let Some(c) = self.conns.get_mut(&conn) {
                        c.req.sent.insert((l, b), (raw, super::UNTAGGED));
                    }
                }
                if code == Code::STORAGE_CAP && !self.capped.contains(&(host, l, b)) {
                    self.memory_report(&l, "a host's ephemeral cap was reached: an entry stays out there until room appears (sent again later)");
                }
            }
            // what it replaced went with it (spec/sync.md §5); else those deletes may go again
            for p in replaced.into_iter().flatten() {
                if let Some(c) = self.conns.get_mut(&conn) {
                    c.req.deleting.remove(&(l, p));
                }
                if code == Code::OK {
                    self.absent_at(Some(host), l, p)?;
                    grew = true;
                }
            }
            if code == Code::STORAGE_CAP {
                self.capped.retain(|(s, l, b)| self.state.entries.contains_key(&(*l, *b)) && !self.state.is_present(s, l, b));
                // the bodies it would carry are judged again (`carried`), in a pass now
                if self.capped.insert((host, l, b)) {
                    self.state.touch(l, b);
                    grew = true;
                }
            } else {
                self.capped.remove(&(host, l, b));
            }
            match code {
                Code::OK => {
                    let new = !self.state.is_present(&host, &l, &b);
                    grew |= new;
                    self.state.set_present(host, l, b, true);
                    if new {
                        self.reached(&l, &b);
                    }
                    // a stamped upload of a deposited entry promoted it
                    self.state.set_deposited(host, l, b, false);
                }
                Code::TOMBSTONED => {
                    self.state.set_gone(host, l, b);
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
                if let Some(t) = self.deposit_seen.get_mut(&(host, l, b)) {
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
        let Some(host) = self.conns.get(&conn).map(|c| c.host) else { return Ok(()) };
        for (b, code) in ids.into_iter().zip(codes) {
            if let Some(c) = self.conns.get_mut(&conn) {
                c.req.deleting.remove(&(l, b));
            }
            match code {
                Code::OK => {
                    self.absent_at(Some(host), l, b)?;
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

    /// Entry `b` under `l` reached a host: when it holds a body of a role commit of this node, the
    /// labels it concerns and those with an entry of it pass again (its held copies may go now,
    /// spec/sync.md §5). A certificate copy places nothing: the commit is placed by its bodies.
    fn reached(&mut self, l: &LabelId, b: &BlobId) {
        let Some(Entry { kind: Kind::Commit { commit, .. }, cert: false, .. }) = self.state.entries.get(&(*l, *b)) else { return };
        let commit = *commit;
        if !self.own(&commit) {
            return;
        }
        let Some(h) = self.engine.header(&commit).filter(|h| h.kind.is_role()) else { return };
        let things: BTreeSet<Tid> = h.aspects.iter().map(|a| a.tid).collect();
        let holding = self.state.labels_of_commit(&commit);
        self.mark_things(&things, &holding);
    }

    /// A deposit's answer; `entries_left` only when the host checked its signature under the
    /// head (a stale one learns nothing: the head comes by the open connection, spec/sync.md §5).
    pub(crate) fn budget(&mut self, conn: ConnId, l: LabelId, b: BlobId, code: Code, entries_left: Option<u64>) -> Result<()> {
        let Some(c) = self.conns.get_mut(&conn) else { return Ok(()) };
        let host = c.host;
        c.req.sent.remove(&(l, b));
        if let Some(n) = entries_left {
            self.deposit_room.insert((host, l), n);
            if let Some(lc) = self.lc_mut(conn, &l) {
                lc.budget = Some(n);
            }
        }
        // a queued deposit's answer
        let now = self.raw_now();
        if let Some(o) = self.outbox.get_mut(&(host, l, b)).filter(|o| o.sent.is_some()) {
            // refused for now (not registered yet, rate limit, budget full while the label's
            // writers are away, the host at a storage cap): sent again until taken or moot; signed by an earlier deposit key
            // (a refreshed deposit seed): the same bytes never verify, so signed again first
            o.tries = o.tries.saturating_add(1);
            o.sent = None;
            let tries = o.tries;
            let resigned = code == Code::NOT_HEAD && self.resign_deposit(&host, &l, &b)?;
            let retry = matches!(code, Code::UNKNOWN_LABEL | Code::RATE_LIMITED | Code::BUDGET_FULL | Code::STORAGE_CAP) || resigned;
            if retry && !self.deposit_moot(&host, &l, &b) {
                // retry_ms, doubling per refusal, at most DEPOSIT_RETRY_CAP_MS; re-signed: at once
                let back = if resigned { 0 } else { self.cfg.retry_ms.saturating_mul(1u64 << (tries - 1).min(20)).min(super::local::DEPOSIT_RETRY_CAP_MS) };
                if let Some(o) = self.outbox.get_mut(&(host, l, b)) {
                    o.after = now.saturating_add(back);
                }
                // a full budget refuses the rest as well: they wait with this one, bodies unsent
                if code == Code::BUDGET_FULL {
                    let span = (host, l, BlobId([0; 32]))..=(host, l, BlobId([0xff; 32]));
                    for o in self.outbox.range_mut(span).map(|(_, o)| o).filter(|o| o.sent.is_none()) {
                        o.after = o.after.max(now.saturating_add(back));
                    }
                }
            } else {
                if retry || code == Code::NOT_HEAD {
                    self.diag(format!("deposit under {l:?} moot after {tries} refusals (code {})", code.0));
                }
                self.outbox.remove(&(host, l, b));
                self.state.remove_out(&host, &l, &b);
            }
        }
        let span = (host, l, BlobId([0; 32]))..=(host, l, BlobId([0xff; 32]));
        if self.outbox.range(span).next().is_none() {
            self.deposit_room.remove(&(host, l));
        }
        match code {
            Code::OK => {
                // room there: what waits at this host and label goes now, not at its back-off (the
                // host does not say when a budget frees)
                let span = (host, l, BlobId([0; 32]))..=(host, l, BlobId([0xff; 32]));
                for o in self.outbox.range_mut(span).map(|(_, o)| o) {
                    o.tries = 0;
                    o.after = 0;
                }
                self.state.set_present(host, l, b, true);
                self.reached(&l, &b);
            }
            Code::NOT_HEAD => {}
            Code::TOMBSTONED => self.state.set_gone(host, l, b),
            c => self.diag(format!("deposit refused: code {}", c.0)),
        }
        Ok(())
    }
}
