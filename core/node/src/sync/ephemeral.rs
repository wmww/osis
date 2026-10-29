//! The ephemeral lane (notes/ephemeral.md Synced ephemeral data): ephemeral commits travel as
//! ordinary entries (sealed with the ephemeral or relay prefix class, wrapped, stamped, uploaded,
//! announced by the server's log and pushes) but are held in memory only, here as blobs per label
//! and in the engine as commit records; nothing of them reaches the store or the sync records.
//! Holders bring what a server or peer lacks: a node lists the ephemeral entries it holds under a
//! label as `gained` in its first Sync of the label on each connection and uploads what the peer
//! wants; an entry received from one server or peer goes to the others it syncs the label with
//! (stamped entries only; own ones are stamped here). Relay-only entries (signals) are delivered
//! and passed to nobody. Per label, the bytes held from others are capped
//! (`SyncConfig::ephemeral_bytes`): past it further ephemeral commits of the label are not
//! applied (`EphemeralRefused`). A writer compacts when held bodies outgrow the state, or when a
//! server refuses for its cap, and deletes what the compaction covers where it uploaded it.

use super::state::ServerKey;
use super::{Action, ConnId, Phase, SyncEngine};
use crate::ephemeral::{EphCommit, EphIngest};
use crate::error::Result;
use crate::events::{Diagnostic, DiagnosticKind};
use crate::labeling::{HeadKeys, delete_item, open_commit, seal_body_as};
use osis_base::{BlobId, CommitId, LabelId, Tid};
use osis_commit::{DeleteKey, EphClass};
use osis_crypto::{Signature, SigningSecret};
use osis_label::Class;
use osis_proto::{Code, Command};
use std::collections::{BTreeMap, BTreeSet};

/// One ephemeral entry held under a label (in memory).
#[derive(Clone)]
pub(crate) struct LaneEntry {
    pub commit: CommitId,
    pub blob: Vec<u8>,
    pub wrap: [u8; osis_crypto::WRAP_LEN],
    /// Under the label's write key (relayed entries keep theirs; own ones are stamped here).
    pub stamp: Option<Signature>,
    /// Built here: not counted against the cap.
    pub own: bool,
    /// What a delete signature by a delete key needs (spec/crypto.md §7): the blob's prefix
    /// salt, the header's blind, the first part's thing, the header's actor and its keys.
    pub salt: [u8; 16],
    pub blind: [u8; 16],
    pub tid: Tid,
    pub actor: Tid,
    pub keys: Vec<DeleteKey>,
}

/// The lane's state (in memory).
#[derive(Default)]
pub(crate) struct Lane {
    pub entries: BTreeMap<(LabelId, BlobId), LaneEntry>,
    pub by_commit: BTreeMap<CommitId, BTreeSet<(LabelId, BlobId)>>,
    /// Entries known held at a server or peer (on the connection up now).
    pub present: BTreeSet<(ServerKey, LabelId, BlobId)>,
    /// Bytes held from others per label.
    pub bytes: BTreeMap<LabelId, u64>,
    /// Labels whose cap was hit (reported once until bytes drop under it).
    pub refused: BTreeSet<LabelId>,
    /// Labels a server refused an ephemeral upload of for its cap since the last compaction.
    pub server_full: BTreeSet<LabelId>,
    /// Per connection and label: whether the first Sync listed the held entries, and those it
    /// listed that the peer has not asked for yet.
    pub announced: BTreeSet<(ConnId, LabelId)>,
    pub gained: BTreeMap<(ConnId, LabelId), BTreeSet<BlobId>>,
    /// Relay-only entries sent and not answered (their statuses are no entry's).
    pub relays: BTreeSet<(LabelId, BlobId)>,
}

impl SyncEngine {
    /// The write key that stamps under `l` of `g` now: an open connection's, else the served
    /// head's (a label synced with nobody, or served to peers).
    fn eph_stamp_key(&mut self, g: &Tid, l: &LabelId) -> Option<SigningSecret> {
        for c in self.conns.values() {
            if let Some(x) = c.labels.get(l).filter(|x| x.phase == Phase::Open)
                && let Some(w) = &x.keys.write
            {
                return Some(w.clone());
            }
        }
        let served = self.served_labels();
        let head = served.get(l)?.head()?.clone();
        let index = self.group_label(g, l).map(|gl| gl.index)?;
        self.engine.head_keys(g, index, &head).ok()?.write
    }

    /// Open connections with label `l` (connection, server key, keys).
    fn eph_conns(&self, l: &LabelId) -> Vec<(ConnId, ServerKey, HeadKeys)> {
        self.conns.iter().filter_map(|(id, c)| c.labels.get(l).filter(|x| x.phase == Phase::Open && c.up).map(|x| (*id, c.server, x.keys.clone()))).collect()
    }

    /// Per step: re-judges held ephemeral commits, compacts where due, sends what was written,
    /// forgets (and deletes where it uploaded) what a compaction covered.
    pub(crate) fn eph_step(&mut self, out: &mut Vec<Action>) -> Result<()> {
        self.engine.rejudge_ephemeral()?;
        let full: Vec<LabelId> = std::mem::take(&mut self.eph.server_full).into_iter().collect();
        let mut commits = Vec::new();
        for l in full {
            let Some(g) = self.group_of(&l) else { continue };
            let scope = self.engine.ephemeral_closure(&g);
            match self.engine.compact_ephemeral(Some(&scope), true)? {
                Some(c) => commits.push(c),
                None => self.eph_report(&l, "a server's ephemeral cap was reached and nothing could be compacted: ephemeral data of this label stops syncing there"),
            }
        }
        if let Some(c) = self.engine.compact_ephemeral(None, false)? {
            commits.push(c);
        }
        commits.extend(self.engine.take_ephemeral()?);
        for c in commits {
            self.eph_place(c, out)?;
        }
        let dropped = self.engine.take_dropped_ephemeral();
        self.eph_forget(&dropped, out)?;
        Ok(())
    }

    fn eph_report(&mut self, l: &LabelId, detail: &str) {
        let now = self.engine.now();
        let tids = self.group_of(l).into_iter().collect();
        self.engine.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::EphemeralRefused, tids, commit: None, peer: None, detail: detail.into() }, now);
        self.engine.core.events.flush();
    }

    /// Places an ephemeral commit built here under every synced label whose closure (ephemeral
    /// placements included) holds its things, one blob per projection the label's actor may
    /// read (spec/sync.md §3), and sends it on every connection where the label is open.
    fn eph_place(&mut self, c: EphCommit, out: &mut Vec<Action>) -> Result<()> {
        let class = Class::of_marker(Some(c.class));
        for (g, gl) in self.labels() {
            if gl.replaced {
                continue;
            }
            let l = gl.id;
            let closure = self.engine.ephemeral_closure(&g);
            let readers: Vec<Option<Tid>> = c.blob.header.aspects.iter().map(|a| closure.contains(&a.tid).then(|| self.engine.ephemeral_reader(&a.tid))).collect();
            if readers.iter().all(Option::is_none) {
                continue;
            }
            let actor = self.engine.group_actor(&g);
            let Some(secret) = self.engine.wrap_secret(&g, None)? else { continue };
            let projections = osis_commit::project(&c.blob, |ai| readers.get(ai).copied().flatten())?;
            let stamp_key = self.eph_stamp_key(&g, &l);
            for p in projections {
                let Some(reader) = p.readers else { continue };
                if reader != actor && !self.engine.may_read(&actor, &reader) {
                    continue;
                }
                let body = crate::labeling::Body { commit: c.id, reader, parts: p.parts.clone(), expires: p.expires, keys: p.keys.clone(), blind: c.blob.header.blind, plaintext: p.plaintext, membership: false };
                let s = seal_body_as(&body, class, &mut *self.rng)?;
                let wrap = osis_crypto::wrap(&secret, &s.id, &s.key)?;
                let stamp = stamp_key.as_ref().map(|w| osis_label::sign_stamp(w, &l, &s.id, &wrap));
                if c.class == EphClass::Relay {
                    self.eph_send_relay(l, s.blob, wrap, stamp, out)?;
                    continue;
                }
                let ai = p.parts.first().map_or(0, |x| x.0);
                let a = c.blob.header.aspects.get(ai);
                let e = LaneEntry { commit: c.id, blob: s.blob, wrap, stamp, own: true, salt: s.salt, blind: c.blob.header.blind, tid: a.map_or(g, |a| a.tid), actor: c.blob.header.actor, keys: p.keys };
                self.eph_keep(l, s.id, e);
                self.eph_spread(l, s.id, None, out)?;
            }
        }
        Ok(())
    }

    /// Keeps an entry under `l` (served to peers from now on).
    fn eph_keep(&mut self, l: LabelId, b: BlobId, e: LaneEntry) {
        if !e.own {
            *self.eph.bytes.entry(l).or_default() += e.blob.len() as u64;
        }
        self.eph.by_commit.entry(e.commit).or_default().insert((l, b));
        self.eph.entries.insert((l, b), e);
        self.state.feed.added(l, b);
    }

    /// Sends a relay-only entry on every connection where `l` is open (and to the served
    /// sessions, as a member peer would push it), stamped.
    fn eph_send_relay(&mut self, l: LabelId, blob: Vec<u8>, wrap: [u8; osis_crypto::WRAP_LEN], stamp: Option<Signature>, out: &mut Vec<Action>) -> Result<()> {
        let blob_id = osis_label::blob_id(&blob);
        for (conn, _, keys) in self.eph_conns(&l) {
            let st = match (stamp, &keys.write) {
                (Some(s), _) => s,
                (None, Some(w)) => osis_label::sign_stamp(w, &l, &blob_id, &wrap),
                (None, None) => continue,
            };
            self.eph.relays.insert((l, blob_id));
            self.command(conn, Command::Upload { label: l, entries: vec![osis_proto::Entry { blob: blob.clone(), wrap, stamp: st }] }, out)?;
        }
        if let Some(stamp) = stamp
            && !self.served.is_empty()
        {
            let labels = self.served_labels();
            let conns: Vec<ConnId> = self.served.keys().copied().collect();
            let r = osis_proto::Relayed { label: l, blob_id, blob, wrap, stamp };
            for c in conns {
                self.serve_with(c, osis_proto::ServerInput::Relay(r.clone()), &labels, out)?;
            }
        }
        Ok(())
    }

    /// Uploads entry `b` of `l` on every connection where the label is open and the peer is not
    /// known to hold it (but `from`, where it came from).
    fn eph_spread(&mut self, l: LabelId, b: BlobId, from: Option<ServerKey>, out: &mut Vec<Action>) -> Result<()> {
        for (conn, server, keys) in self.eph_conns(&l) {
            if Some(server) == from || self.eph.present.contains(&(server, l, b)) {
                continue;
            }
            self.eph_upload(conn, l, &[b], &keys, out)?;
        }
        Ok(())
    }

    /// Uploads lane entries `ids` of `l` on `conn`: stamped ones as they are, own unstamped ones
    /// stamped under the connection's write key.
    fn eph_upload(&mut self, conn: ConnId, l: LabelId, ids: &[BlobId], keys: &HeadKeys, out: &mut Vec<Action>) -> Result<()> {
        let mut entries = Vec::new();
        for b in ids {
            let Some(e) = self.eph.entries.get_mut(&(l, *b)) else { continue };
            let stamp = match (e.stamp, &keys.write) {
                (Some(s), _) => s,
                (None, Some(w)) if e.own => {
                    let s = osis_label::sign_stamp(w, &l, b, &e.wrap);
                    e.stamp = Some(s);
                    s
                }
                _ => continue,
            };
            entries.push(osis_proto::Entry { blob: e.blob.clone(), wrap: e.wrap, stamp });
        }
        if !entries.is_empty() {
            self.command(conn, Command::Upload { label: l, entries }, out)?;
        }
        Ok(())
    }

    /// The held entry IDs of `l` a first Sync on `conn` lists as gained (none past the message
    /// cap: then everything goes after the Sync, `eph_synced`).
    pub(crate) fn eph_gained(&mut self, conn: ConnId, l: LabelId) -> Vec<BlobId> {
        if !self.eph.announced.insert((conn, l)) {
            return Vec::new();
        }
        let ids: BTreeSet<BlobId> = self.eph.entries.range((l, BlobId([0; 32]))..).take_while(|((x, _), _)| *x == l).map(|((_, b), _)| *b).collect();
        if ids.is_empty() || ids.len() > osis_proto::msg::MAX_GAINED {
            if !ids.is_empty() {
                self.eph.announced.remove(&(conn, l));
            }
            return Vec::new();
        }
        self.eph.gained.insert((conn, l), ids.clone());
        ids.into_iter().collect()
    }

    /// The peer asked for gained IDs it lacks: the lane's go up. The rest of `ids`.
    pub(crate) fn eph_want(&mut self, conn: ConnId, l: LabelId, ids: Vec<BlobId>, out: &mut Vec<Action>) -> Result<Vec<BlobId>> {
        let (mine, rest): (Vec<BlobId>, Vec<BlobId>) = ids.into_iter().partition(|b| self.eph.entries.contains_key(&(l, *b)));
        if let Some(g) = self.eph.gained.get_mut(&(conn, l)) {
            for b in &mine {
                g.remove(b);
            }
        }
        if !mine.is_empty()
            && let Some(keys) = self.lc(conn, &l).map(|x| x.keys.clone())
        {
            self.eph_upload(conn, l, &mine, &keys, out)?;
        }
        Ok(rest)
    }

    /// A Sync of `l` on `conn` ran through: what it listed as gained and the peer did not want,
    /// the peer holds; anything else held goes up (an announcement that did not fit).
    pub(crate) fn eph_synced(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<Action>) -> Result<()> {
        let Some(server) = self.conns.get(&conn).map(|c| c.server) else { return Ok(()) };
        if let Some(g) = self.eph.gained.remove(&(conn, l)) {
            for b in g {
                self.eph.present.insert((server, l, b));
            }
        }
        if self.eph.announced.contains(&(conn, l)) {
            let missing: Vec<BlobId> = self.eph.entries.range((l, BlobId([0; 32]))..).take_while(|((x, _), _)| *x == l).map(|((_, b), _)| *b).filter(|b| !self.eph.present.contains(&(server, l, *b))).collect();
            if !missing.is_empty()
                && let Some(keys) = self.lc(conn, &l).map(|x| x.keys.clone())
            {
                self.eph_upload(conn, l, &missing, &keys, out)?;
            }
        } else {
            // not announced (too many): everything held goes, the peer keeps one copy
            self.eph.announced.insert((conn, l));
            let all: Vec<BlobId> = self.eph.entries.range((l, BlobId([0; 32]))..).take_while(|((x, _), _)| *x == l).map(|((_, b), _)| *b).collect();
            if let Some(keys) = self.lc(conn, &l).map(|x| x.keys.clone()) {
                self.eph_upload(conn, l, &all, &keys, out)?;
            }
        }
        Ok(())
    }

    /// Statuses of lane uploads; the rest are returned for the durable path.
    pub(crate) fn eph_status(&mut self, conn: ConnId, l: LabelId, ids: Vec<BlobId>, codes: Vec<Code>) -> (Vec<BlobId>, Vec<Code>) {
        let Some(server) = self.conns.get(&conn).map(|c| c.server) else { return (ids, codes) };
        let mut rest = (Vec::new(), Vec::new());
        for (b, code) in ids.into_iter().zip(codes) {
            if self.eph.relays.remove(&(l, b)) {
                continue;
            }
            if !self.eph.entries.contains_key(&(l, b)) {
                rest.0.push(b);
                rest.1.push(code);
                continue;
            }
            match code {
                Code::OK => {
                    self.eph.present.insert((server, l, b));
                }
                Code::STORAGE_CAP => {
                    self.eph.server_full.insert(l);
                }
                Code::TOMBSTONED => {
                    self.eph.present.remove(&(server, l, b));
                }
                c => self.diag(format!("ephemeral upload refused: code {}", c.0)),
            }
        }
        rest
    }

    /// An ephemeral or relay-only entry arrived under `l` (a log event, a fetch, a peer's
    /// upload): kept and applied, or delivered; `server` where it came from.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn eph_added(&mut self, server: Option<ServerKey>, l: LabelId, b: BlobId, blob: Vec<u8>, wrap: [u8; osis_crypto::WRAP_LEN], stamp: Option<Signature>, class: Class, out: &mut Vec<Action>) -> Result<()> {
        if class == Class::Relay {
            return self.relay_in(l, b, &blob, &wrap);
        }
        if self.eph.entries.contains_key(&(l, b)) {
            if let Some(s) = server {
                self.eph.present.insert((s, l, b));
            }
            return Ok(());
        }
        let Some(g) = self.group_of(&l) else { return Ok(()) };
        let secrets = self.read_secrets(&g);
        let Some((_, key)) = osis_label::unwrap_any(secrets.iter(), &b, &wrap) else { return Ok(()) };
        let (_, cb) = match open_commit(&blob, &key) {
            Ok(x) => x,
            Err(e) => {
                self.diag(format!("ephemeral blob {b:?}: {e}"));
                return Ok(());
            }
        };
        if cb.header.ephemeral != Some(EphClass::Plain) {
            self.diag(format!("ephemeral blob {b:?}: not an ephemeral commit"));
            return Ok(());
        }
        // the cap on what others make this node hold per label (notes/ephemeral.md Bounds)
        let size = blob.len() as u64;
        let used = self.eph.bytes.get(&l).copied().unwrap_or(0);
        if used.saturating_add(size) > self.cfg.ephemeral_bytes {
            if self.eph.refused.insert(l) {
                self.eph_report(&l, "this node's ephemeral cap for the label was reached: its further ephemeral data is not applied here");
            }
            return Ok(());
        }
        let commit = cb.id();
        let h = cb.header.clone();
        match self.engine.ingest_ephemeral(cb) {
            Ok(EphIngest::Held { .. } | EphIngest::Pending) => {}
            Ok(EphIngest::Delivered { .. }) => return Ok(()),
            Err(e) => {
                self.diag(format!("ephemeral commit {commit:?}: {e}"));
                return Ok(());
            }
        }
        let salt = osis_label::Prefix::parse(&blob).map(|p| *p.salt()).unwrap_or_default();
        let parts = osis_commit::CommitBlob::decode(&osis_label::open(&blob, &key).map(|x| x.1).unwrap_or_default()).ok().and_then(|c| c.parts.first().map(|p| p.ai)).unwrap_or(0);
        let a = h.aspects.get(parts);
        let keys = a.map(|a| a.keys.iter().filter_map(|i| h.keys.get(*i).copied()).collect()).unwrap_or_default();
        let e = LaneEntry { commit, blob, wrap, stamp, own: false, salt, blind: h.blind, tid: a.map_or(g, |a| a.tid), actor: h.actor, keys };
        if let Some(s) = server {
            self.eph.present.insert((s, l, b));
        }
        self.eph_keep(l, b, e);
        if stamp.is_some() {
            self.eph_spread(l, b, server, out)?;
        }
        Ok(())
    }

    /// A relay-only entry with its wrap (a push, a peer's upload): delivered once.
    pub(crate) fn relay_in(&mut self, l: LabelId, b: BlobId, blob: &[u8], wrap: &[u8; osis_crypto::WRAP_LEN]) -> Result<()> {
        let Some(g) = self.group_of(&l) else { return Ok(()) };
        let secrets = self.read_secrets(&g);
        let Some((_, key)) = osis_label::unwrap_any(secrets.iter(), &b, wrap) else { return Ok(()) };
        let (_, cb) = match open_commit(blob, &key) {
            Ok(x) => x,
            Err(e) => {
                self.diag(format!("relay-only blob {b:?}: {e}"));
                return Ok(());
            }
        };
        if cb.header.ephemeral != Some(EphClass::Relay) {
            self.diag(format!("relay-only blob {b:?}: not a relay-only commit"));
            return Ok(());
        }
        let id = cb.id();
        if let Err(e) = self.engine.ingest_ephemeral(cb) {
            self.diag(format!("relay-only commit {id:?}: {e}"));
        }
        Ok(())
    }

    /// An ephemeral entry was deleted at `server`: no longer present there.
    pub(crate) fn eph_deleted(&mut self, server: Option<ServerKey>, l: LabelId, b: BlobId) -> bool {
        if !self.eph.entries.contains_key(&(l, b)) {
            return false;
        }
        if let Some(s) = server {
            self.eph.present.remove(&(s, l, b));
        }
        true
    }

    /// Forgets the entries of held ephemeral commits the engine dropped (covered by a
    /// compaction, expired); a writer deletes them where they were uploaded (by the part's
    /// level-3 delete key and the label's write key, spec/sync.md §5).
    fn eph_forget(&mut self, commits: &[CommitId], out: &mut Vec<Action>) -> Result<()> {
        for c in commits {
            let Some(keys) = self.eph.by_commit.remove(c) else { continue };
            for (l, b) in keys {
                let Some(e) = self.eph.entries.remove(&(l, b)) else { continue };
                if !e.own
                    && let Some(n) = self.eph.bytes.get_mut(&l)
                {
                    *n = n.saturating_sub(e.blob.len() as u64);
                    if *n < self.cfg.ephemeral_bytes {
                        self.eph.refused.remove(&l);
                    }
                }
                self.state.feed.deleted(l, b);
                let dks = self.engine.ephemeral_delete_secrets_for(&e.tid, &e.actor, &e.keys);
                for (conn, server, hk) in self.eph_conns(&l) {
                    if !self.eph.present.remove(&(server, l, b)) {
                        continue;
                    }
                    if let Some(item) = delete_item(&hk, &l, b, None, Some((&e.salt, &e.blind)), &dks) {
                        self.command(conn, Command::Delete { label: l, items: vec![item] }, out)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// A connection ended: what it knew of its peer goes with it.
    pub(crate) fn eph_lost(&mut self, conn: ConnId, server: ServerKey) {
        self.eph.present.retain(|(s, _, _)| *s != server);
        self.eph.announced.retain(|(c, _)| *c != conn);
        self.eph.gained.retain(|(c, _), _| *c != conn);
    }

    /// Ephemeral entries held under `l` (serving peers): ID and entry.
    pub(crate) fn eph_entries_of<'a>(lane: &'a Lane, l: &LabelId) -> impl Iterator<Item = (BlobId, &'a LaneEntry)> {
        let l = *l;
        lane.entries.range((l, BlobId([0; 32]))..).take_while(move |((x, _), _)| *x == l).map(|((_, b), e)| (*b, e))
    }

    /// Ephemeral bytes held from others under `l` (tests, diagnostics).
    pub fn ephemeral_bytes(&self, l: &LabelId) -> u64 {
        self.eph.bytes.get(l).copied().unwrap_or(0)
    }

    /// Ephemeral entries held under `l` (tests, diagnostics).
    pub fn ephemeral_entries(&self, l: &LabelId) -> usize {
        Self::eph_entries_of(&self.eph, l).count()
    }
}
