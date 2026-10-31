//! Receipts-only reads (notes/sync.md Receipts-only reads; spec/permissions.md §5.1, §5.3): a
//! label of a group this node holds none of is opened, its log listed without blob bytes, its
//! commit blobs alone fetched (chunk, tree-node and page entries carry filler wraps no read
//! secret opens), opened, and their verified headers recorded as received
//! (`Engine::record_header`). Nothing is kept, applied, uploaded, deleted or placed: no pass
//! runs on such a label, no step is recorded or registered, no subscription is made, and its
//! log events never reach the entry records (`log_events`).

use super::state::ServerKey;
use super::{Action, ConnId, Phase, SyncEngine};
use crate::error::Result;
use crate::labeling::open_commit;
use osis_base::{BlobId, LabelId, Tid};
use osis_proto::{ClientEvent, Command, Event as LogEvent};
use std::collections::{BTreeMap, BTreeSet};

/// One label read for receipts.
pub(crate) struct Read {
    pub group: Tid,
    /// Callers that asked for it and have not ended it (`read_receipts`, `end_receipts`).
    users: u32,
    /// The label's servers (peers excluded: a receipts-only read is never served by a co-reader).
    pub servers: Vec<ServerKey>,
    /// Per server read on its current connection: the log listed to its end, and the commit
    /// blobs asked for and not here yet.
    at: BTreeMap<ServerKey, AtServer>,
    /// Commit blobs whose header was taken (recorded or not verifiable here): not fetched again.
    seen: BTreeSet<BlobId>,
}

#[derive(Default)]
struct AtServer {
    listed: bool,
    fetching: BTreeSet<BlobId>,
    /// Listed entries no held read secret opened (yet): tried again when secrets arrive.
    unopened: BTreeMap<BlobId, Vec<u8>>,
}

/// The label of a data event (what a receipts-only label answers itself).
fn data_label(e: &ClientEvent) -> Option<LabelId> {
    use ClientEvent as E;
    match e {
        E::Events { label, .. } | E::Fetched { label, .. } | E::Synced { label } | E::Want { label, .. } | E::NeedReconcile { label } | E::Reconciled { label, .. } | E::EntryStatus { label, .. } | E::DeleteStatus { label, .. } | E::Budget { label, .. } => Some(*label),
        _ => None,
    }
}

impl SyncEngine {
    /// Marks `group` as held by this node for receipts only (`on`), or held again: its labels
    /// are not synced (no download, no pass, nothing placed there); a demotion reads them for
    /// receipts (`read_receipts`). What is already stored stays, no longer updated.
    pub fn set_receipts_only(&mut self, group: Tid, on: bool) -> Vec<Action> {
        self.state.set_receipts_only(group, on);
        self.served_cache = None;
        if on {
            // its labels' sessions stop here: nothing more runs on them
            let labels: BTreeSet<LabelId> = self.engine.labels_of(&group).iter().map(|l| l.id).collect();
            for (id, c) in self.conns.iter_mut() {
                for l in c.labels.iter().filter(|(l, x)| labels.contains(l) && !x.receipts).map(|(l, _)| *l) {
                    self.unsubscribe.insert((*id, l));
                }
                c.labels.retain(|l, x| !labels.contains(l) || x.receipts);
            }
        }
        self.handle(super::Event::Local)
    }

    /// Groups this node holds for receipts only (`set_receipts_only`).
    pub fn receipts_only(&self) -> &BTreeSet<Tid> {
        &self.state.receipts_only
    }

    /// The receipts-only groups holding any of `things` as far as this node knows: the group
    /// itself, or a thing its known closure holds (the rest of its closure is not here).
    pub fn receipts_groups(&mut self, things: &BTreeSet<Tid>) -> Vec<Tid> {
        let gs: Vec<Tid> = self.state.receipts_only.iter().copied().collect();
        gs.into_iter().filter(|g| things.contains(g) || self.engine.closure(g).iter().any(|t| things.contains(t))).collect()
    }

    /// Starts a receipts-only read of every label of `groups` held for receipts only (others
    /// are left alone: a held group is synced). `receipts_read` tells when it is done;
    /// `end_receipts` ends it.
    pub fn read_receipts(&mut self, groups: &[Tid]) -> Vec<Action> {
        for g in groups.iter().filter(|g| self.state.receipts_only.contains(g)) {
            for l in self.engine.labels_of(g) {
                if self.state.retired.contains(&l.id) {
                    continue;
                }
                let r = self.receipts.entry(l.id).or_insert_with(|| Read { group: *g, users: 0, servers: Vec::new(), at: BTreeMap::new(), seen: BTreeSet::new() });
                r.users += 1;
                r.servers = l.servers.iter().filter(|a| !super::peers::is_peer(a)).map(|a| a.key).collect();
            }
        }
        self.handle(super::Event::Local)
    }

    /// Whether the receipts-only reads of `groups` are done: `None` while one runs, `Err` with
    /// the groups whose read cannot finish (a label with no server, or one no held key opens at
    /// some server), `Ok` once every label was listed to its end at each of its servers and
    /// every commit blob listed there was taken.
    pub fn receipts_read(&self, groups: &[Tid]) -> Option<std::result::Result<(), Vec<Tid>>> {
        let mut bad = Vec::new();
        let mut done = true;
        for (l, r) in self.receipts.iter().filter(|(_, r)| groups.contains(&r.group)) {
            let failed = self.conns.values().any(|c| c.labels.get(l).is_some_and(|x| x.receipts && x.phase == Phase::Failed));
            if r.servers.is_empty() || failed {
                bad.push(r.group);
                continue;
            }
            done &= r.servers.iter().all(|s| r.at.get(s).is_some_and(|a| a.listed && a.fetching.is_empty()));
        }
        if !bad.is_empty() {
            bad.sort();
            bad.dedup();
            return Some(Err(bad));
        }
        done.then_some(Ok(()))
    }

    /// Ends the receipts-only reads of `groups` that `read_receipts` started (one call each):
    /// a read nobody waits for any more closes.
    pub fn end_receipts(&mut self, groups: &[Tid]) {
        for r in self.receipts.values_mut().filter(|r| groups.contains(&r.group)) {
            r.users = r.users.saturating_sub(1);
        }
        let gone: BTreeSet<LabelId> = self.receipts.iter().filter(|(_, r)| r.users == 0).map(|(l, _)| *l).collect();
        self.receipts.retain(|l, _| !gone.contains(l));
        for c in self.conns.values_mut() {
            c.labels.retain(|l, x| !(x.receipts && gone.contains(l)));
        }
    }

    /// Receipts-only labels to open: their group, label and servers.
    pub(crate) fn receipts_wanted(&self) -> Vec<(Tid, LabelId, Vec<ServerKey>)> {
        self.receipts.iter().map(|(l, r)| (r.group, *l, r.servers.clone())).collect()
    }

    /// Whether `l` is read for receipts only on `conn`.
    pub(crate) fn receipts_lc(&self, conn: ConnId, l: &LabelId) -> bool {
        self.lc(conn, l).is_some_and(|x| x.receipts)
    }

    /// A receipts-only label starts (again) on `conn`: what an earlier connection read there
    /// counts no more.
    pub(crate) fn receipts_start(&mut self, conn: ConnId, l: &LabelId) {
        let Some(server) = self.conns.get(&conn).map(|c| c.server) else { return };
        if let Some(r) = self.receipts.get_mut(l) {
            r.at.remove(&server);
        }
    }

    /// Lists a receipts-only label from no cursor, without blob bytes (each commit blob is
    /// fetched alone), announcing nothing.
    pub(crate) fn receipts_sync(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<Action>) -> Result<()> {
        let now = self.raw_now();
        let Some(server) = self.conns.get(&conn).map(|c| c.server) else { return Ok(()) };
        let Some(lc) = self.lc_mut(conn, &l) else { return Ok(()) };
        lc.syncing = true;
        lc.last_sync = now;
        if let Some(r) = self.receipts.get_mut(&l) {
            r.at.insert(server, AtServer::default());
        }
        self.command(conn, Command::Sync { label: l, cursor: None, inline_limit: 0, entries: Vec::new(), gained: Vec::new() }, out)
    }

    /// A data event on a receipts-only label (`data_label`); false when `e` is none.
    pub(crate) fn receipts_event(&mut self, conn: ConnId, e: &ClientEvent, out: &mut Vec<Action>) -> Result<bool> {
        let Some(l) = data_label(e).filter(|l| self.receipts_lc(conn, l)) else { return Ok(false) };
        let Some(server) = self.conns.get(&conn).map(|c| c.server) else { return Ok(true) };
        let open = self.lc(conn, &l).is_some_and(|x| x.phase == Phase::Open);
        let secrets = self.secrets_count();
        match e {
            ClientEvent::Events { events, .. } if open => {
                for ev in events {
                    match ev {
                        LogEvent::Added { blob_id, blob, wrap, .. } => self.receipts_entry(conn, server, l, *blob_id, blob.as_deref(), wrap, out)?,
                        LogEvent::Head(step) => self.new_head(conn, l, step.clone(), out)?,
                        LogEvent::Deleted(_) | LogEvent::Pending { .. } => {}
                    }
                }
            }
            ClientEvent::Fetched { items, .. } => {
                for f in items {
                    match &f.entry {
                        Some((blob, wrap, _)) => self.receipts_entry(conn, server, l, f.blob_id, Some(blob), wrap, out)?,
                        // not there (deleted since it was listed): nothing to take
                        None => self.receipts_taken(server, l, f.blob_id),
                    }
                }
            }
            ClientEvent::Synced { .. } => {
                if let Some(lc) = self.lc_mut(conn, &l) {
                    lc.syncing = false;
                    lc.synced = true;
                }
                if let Some(a) = self.receipts.get_mut(&l).and_then(|r| r.at.get_mut(&server)) {
                    a.listed = true;
                }
            }
            // nothing is announced or uploaded under a receipts-only label
            _ => {}
        }
        // the group's membership commits brought secrets: entries they open are fetched now
        let mut before = secrets;
        while self.secrets_count() != before {
            before = self.secrets_count();
            let retry: Vec<(BlobId, Vec<u8>)> = self.receipts.get_mut(&l).and_then(|r| r.at.get_mut(&server)).map(|a| std::mem::take(&mut a.unopened).into_iter().collect()).unwrap_or_default();
            for (b, wrap) in retry {
                self.receipts_entry(conn, server, l, b, None, &wrap, out)?;
            }
        }
        Ok(true)
    }

    /// Fetches refused on a receipts-only label count as taken (the read does not wait on them).
    pub(crate) fn receipts_refused(&mut self, conn: ConnId, l: &LabelId, fetch: &[BlobId]) {
        let Some(server) = self.conns.get(&conn).map(|c| c.server) else { return };
        for b in fetch {
            self.receipts_taken(server, *l, *b);
        }
    }

    fn receipts_taken(&mut self, server: ServerKey, l: LabelId, b: BlobId) {
        if let Some(a) = self.receipts.get_mut(&l).and_then(|r| r.at.get_mut(&server)) {
            a.fetching.remove(&b);
        }
    }

    /// One listed or fetched entry of a receipts-only label: a commit blob (its wrap opens under
    /// a held read secret) is fetched, then its header recorded; anything else is passed over.
    #[allow(clippy::too_many_arguments)]
    fn receipts_entry(&mut self, conn: ConnId, server: ServerKey, l: LabelId, b: BlobId, blob: Option<&[u8]>, wrap: &[u8], out: &mut Vec<Action>) -> Result<()> {
        let Some(group) = self.receipts.get(&l).map(|r| r.group) else { return Ok(()) };
        if self.receipts.get(&l).is_some_and(|r| r.seen.contains(&b)) {
            self.receipts_taken(server, l, b);
            return Ok(());
        }
        // ephemeral and relay-only entries: never in a frontier (spec/permissions.md §5.2)
        if blob.is_some_and(|x| osis_label::Prefix::parse(x).is_ok_and(|p| p.class() != osis_label::Class::Durable)) {
            self.receipts_taken(server, l, b);
            return Ok(());
        }
        let secrets = self.read_secrets(&group);
        let Some((_, key)) = osis_label::unwrap_any(secrets.iter(), &b, wrap) else {
            self.receipts_taken(server, l, b);
            if let Some(a) = self.receipts.get_mut(&l).and_then(|r| r.at.get_mut(&server)) {
                a.unopened.insert(b, wrap.to_vec());
            }
            return Ok(());
        };
        let Some(bytes) = blob else {
            let Some(a) = self.receipts.get_mut(&l).and_then(|r| r.at.get_mut(&server)) else { return Ok(()) };
            if a.fetching.insert(b) {
                self.command(conn, Command::Fetch { label: l, ids: vec![b] }, out)?;
            }
            return Ok(());
        };
        match open_commit(bytes, &key) {
            // the group's membership commits apply: their `/secrets` open the rest of the label
            // (a group with secrets of its own seals them only there); applying records them
            Ok((pt, c)) if c.header.kind.is_membership() => {
                if let Err(e) = self.engine.ingest(&pt, Vec::new()) {
                    self.diag(format!("ingest {:?}: {e}", c.id()));
                }
                self.engine.reexamine()?;
            }
            Ok((_, c)) => {
                if !self.engine.record_header(&c)? {
                    self.diag(format!("label {l:?}: header of {:?} not verifiable here: no receipt", c.id()));
                }
            }
            Err(e) => self.diag(format!("label {l:?}: blob {b:?}: {e}")),
        }
        if let Some(r) = self.receipts.get_mut(&l) {
            r.seen.insert(b);
        }
        self.receipts_taken(server, l, b);
        Ok(())
    }
}
