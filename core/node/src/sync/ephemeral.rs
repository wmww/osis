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

/// Where an ephemeral or relay-only entry came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelayFrom {
    /// A server or a peer this node dialed (`None`: a bundle, nobody).
    Server(Option<ServerKey>),
    /// A session this node serves.
    Served(ConnId),
}

impl RelayFrom {
    fn server(self) -> Option<ServerKey> {
        match self {
            RelayFrom::Server(s) => s,
            RelayFrom::Served(_) => None,
        }
    }
}
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
    /// Labels force-compacted since an entry of new writes (not a cover) was kept under them:
    /// not forced again until one is (holders of a label a server cannot fit compacted each
    /// other's concurrent covers forever, every cover refused), unless for `own_full`.
    pub forced: BTreeSet<LabelId>,
    /// Per label, the servers that refused an own cover for their cap since this node last
    /// compacted the label: forced again (past `forced`) at once and when another node's cover
    /// is kept under it, by a cover that deletes an entry held at such a server (concurrent
    /// covers to one full server: the refused one stayed out, its writes with it, while the
    /// server held the other). Not for own plain entries (`forced` covers those) nor re-armed by
    /// plain entries of others: an entry refused for good was re-uploaded at every write.
    pub own_full: BTreeMap<LabelId, BTreeSet<ServerKey>>,
    /// Per connection and label: whether the first Sync listed the held entries, and those it
    /// listed that the peer has not asked for yet.
    pub announced: BTreeSet<(ConnId, LabelId)>,
    pub gained: BTreeMap<(ConnId, LabelId), BTreeSet<BlobId>>,
    /// Lane uploads (relay-only ones included) and deletes sent and not answered: their
    /// statuses are the lane's, never a sync record's.
    pub uploads: BTreeSet<(ConnId, LabelId, BlobId)>,
    pub deletes: BTreeSet<(ConnId, LabelId, BlobId)>,
    /// (server, label) reconciled since start, and the reconciliations running (`sync_label`).
    pub reconciled: BTreeSet<(ServerKey, LabelId)>,
    pub reconciling: BTreeSet<(ConnId, LabelId)>,
    /// Entries whose commit waits for its author's record (not verified: neither applied, served
    /// nor spread), with where they came from; their bytes per label (`PENDING_SHARE`).
    pub pending: BTreeMap<(LabelId, BlobId), (LaneEntry, Option<ServerKey>)>,
    pub pending_bytes: BTreeMap<LabelId, u64>,
    /// Held entry IDs by blob (serving a fetch by ID).
    pub by_blob: BTreeSet<(BlobId, LabelId)>,
    /// Relay-only entries received (`RelaySeen`).
    pub relays: RelaySeen,
}

/// The share of `SyncConfig::ephemeral_bytes` a label's unverified entries (waiting for their
/// author's record) may take. Resource bound: past it further such entries are not kept (they
/// come back at a restart's reconciliation); 1 (the whole cap): a writer's commits under made-up
/// authors could fill what honest ones need; infinity (none): an honest commit arriving before
/// its author's record is lost until then.
const PENDING_SHARE: u64 = 4;

/// Relay-only entries remembered as received, node-wide, until their prefix expiry. Resource
/// bound against hostile writers: past it the earliest-expiring is forgotten and its expiry
/// becomes its label's floor, at or below which relay-only entries are dropped, so none is
/// delivered twice (0: only increasing expiries pass; infinity: memory grows with every signal of
/// the replay window). About 200 bytes each: 13 MiB at the bound.
const RELAYS_REMEMBERED: usize = 1 << 16;

/// Relay-only entries received: (label, blob) until their prefix expiry, and a floor per label.
#[derive(Default)]
pub(crate) struct RelaySeen {
    ids: std::collections::HashSet<(LabelId, BlobId)>,
    by_expiry: BTreeSet<(u64, LabelId, BlobId)>,
    floor: BTreeMap<LabelId, u64>,
}

impl RelaySeen {
    /// Whether relay-only entry `b` of `l`, expiring at `t`, is seen here for the first time
    /// (`now` wall ms): not a repeat, not at or below the label's floor.
    pub(crate) fn first(&mut self, l: LabelId, b: BlobId, t: u64, now: u64) -> bool {
        if !self.fresh(l, b, t, now) {
            return false;
        }
        self.record(l, b, t);
        true
    }

    /// Whether relay-only entry `b` of `l`, expiring at `t`, would be seen here for the first
    /// time, without recording it (checked before opening it; recorded once verified, so a
    /// stranger's junk cannot raise a label's floor).
    pub(crate) fn fresh(&mut self, l: LabelId, b: BlobId, t: u64, now: u64) -> bool {
        while let Some(x) = self.by_expiry.first().copied()
            && x.0 <= now
        {
            self.by_expiry.pop_first();
            self.ids.remove(&(x.1, x.2));
        }
        self.floor.retain(|_, f| *f > now);
        !(self.floor.get(&l).is_some_and(|f| t <= *f) || self.ids.contains(&(l, b)))
    }

    /// Records relay-only entry `b` of `l`, expiring at `t`, as seen.
    pub(crate) fn record(&mut self, l: LabelId, b: BlobId, t: u64) {
        if !self.ids.insert((l, b)) {
            return;
        }
        self.by_expiry.insert((t, l, b));
        if self.ids.len() > RELAYS_REMEMBERED
            && let Some((t0, l0, b0)) = self.by_expiry.pop_first()
        {
            self.ids.remove(&(l0, b0));
            let f = self.floor.entry(l0).or_default();
            *f = (*f).max(t0);
        }
    }
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
        self.eph_promote(out)?;
        let full: Vec<LabelId> = std::mem::take(&mut self.eph.server_full).into_iter().collect();
        let mut commits = Vec::new();
        let mut retry = Vec::new();
        for l in full {
            let first = self.eph.forced.insert(l);
            let at = if first { None } else { self.eph.own_full.get(&l).cloned() };
            if !first && at.is_none() {
                continue;
            }
            let Some(g) = self.group_of(&l) else { continue };
            let scope = self.engine.ephemeral_closure(&g);
            // past `forced`: only a cover deleting an entry where an own one was refused
            let lane = &self.eph;
            let frees = |c: &CommitId| at.as_ref().is_none_or(|at| lane.by_commit.get(c).is_some_and(|bs| bs.iter().any(|(l2, b)| at.iter().any(|s| lane.present.contains(&(*s, *l2, *b))))));
            match self.engine.compact_ephemeral_if(Some(&scope), true, &frees)? {
                Some(c) => {
                    commits.push(c);
                    retry.push(l);
                    self.eph.own_full.remove(&l);
                }
                None if first => self.eph_report(&l, "a server's ephemeral cap was reached and nothing could be compacted: ephemeral data of this label stops syncing there"),
                None => {}
            }
        }
        if let Some(c) = self.engine.compact_ephemeral(None, false)? {
            commits.push(c);
        }
        commits.extend(self.engine.take_ephemeral()?);
        // what a compaction covers goes first: deleted before its cover goes up on the same
        // connection, so a server at its cap takes the cover
        let dropped = self.engine.take_dropped_ephemeral();
        self.eph_forget(&dropped, out)?;
        for c in commits {
            self.eph_place(c, out)?;
        }
        // entries a full server refused go again after a compaction made room
        for l in retry {
            let ids: Vec<BlobId> = Self::eph_entries_of(&self.eph, &l).map(|(b, _)| b).collect();
            for b in ids {
                self.eph_spread(l, b, None, out)?;
            }
        }
        Ok(())
    }

    /// Entries whose commit was waiting for its author's record: held now, they join the lane
    /// and spread; refused meanwhile (bad signature, invalid input), they go.
    fn eph_promote(&mut self, out: &mut Vec<Action>) -> Result<()> {
        if self.eph.pending.is_empty() {
            return Ok(());
        }
        let keys: Vec<(LabelId, BlobId)> = self.eph.pending.keys().copied().collect();
        for (l, b) in keys {
            let Some((e, _)) = self.eph.pending.get(&(l, b)) else { continue };
            let c = e.commit;
            let held = self.engine.holds_ephemeral(&c);
            if !held && self.engine.pending_ephemeral(&c) {
                continue;
            }
            let Some((e, from)) = self.eph.pending.remove(&(l, b)) else { continue };
            if let Some(n) = self.eph.pending_bytes.get_mut(&l) {
                *n = n.saturating_sub(e.blob.len() as u64);
            }
            if held && !self.eph.entries.contains_key(&(l, b)) {
                let stamped = e.stamp.is_some();
                self.eph_keep(l, b, e);
                if stamped {
                    self.eph_spread(l, b, from, out)?;
                }
            }
        }
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
            let inside: Vec<bool> = c.blob.header.aspects.iter().map(|a| self.engine.in_ephemeral_closure(&g, &a.tid)).collect();
            // the records of the owner chains of the things inside go along
            let mut chains: BTreeSet<Tid> = BTreeSet::new();
            for (a, _) in c.blob.header.aspects.iter().zip(&inside).filter(|(_, i)| **i) {
                let mut cur = a.tid;
                while let Some(o) = self.engine.ephemeral_thing(&cur).and_then(|_| self.engine.owner(&cur)) {
                    if !chains.insert(o) {
                        break;
                    }
                    cur = o;
                }
            }
            let readers: Vec<Option<Tid>> = c.blob.header.aspects.iter().zip(&inside).map(|(a, i)| (*i || (a.ak.as_str() == "/created" && chains.contains(&a.tid))).then(|| self.engine.ephemeral_reader(&a.tid))).collect();
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
        if !self.engine.ephemeral_is_cover(&e.commit) {
            self.eph.forced.remove(&l);
        }
        // another holder's cover: an own cover refused meanwhile may now replace it there
        if !e.own && self.eph.own_full.contains_key(&l) && self.engine.ephemeral_is_cover(&e.commit) {
            self.eph.server_full.insert(l);
        }
        if !e.own {
            *self.eph.bytes.entry(l).or_default() += e.blob.len() as u64;
        }
        self.eph.by_commit.entry(e.commit).or_default().insert((l, b));
        self.eph.by_blob.insert((b, l));
        self.eph.entries.insert((l, b), e);
        self.state.feed.added(l, b);
    }

    /// Sends a relay-only entry on every connection where `l` is open (and to the served
    /// sessions, as a member peer would push it), stamped.
    fn eph_send_relay(&mut self, l: LabelId, blob: Vec<u8>, wrap: [u8; osis_crypto::WRAP_LEN], stamp: Option<Signature>, out: &mut Vec<Action>) -> Result<()> {
        let blob_id = osis_label::blob_id(&blob);
        if blob.len() > osis_base::format::MAX_RELAY_BLOB {
            self.eph_report(&l, "a signal too large for a relay-only blob was not sent");
            return Ok(());
        }
        // never delivered here again (a member peer's path may bring it back)
        let t = osis_label::Prefix::parse(&blob).ok().and_then(|p| p.expiry()).map_or(0, |t| t.0);
        let now = self.now();
        self.eph.relays.first(l, blob_id, t, now);
        for (conn, _, keys) in self.eph_conns(&l) {
            let st = match (stamp, &keys.write) {
                (Some(s), _) => s,
                (None, Some(w)) => osis_label::sign_stamp(w, &l, &blob_id, &wrap),
                (None, None) => continue,
            };
            self.eph.uploads.insert((conn, l, blob_id));
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
    pub(crate) fn eph_upload(&mut self, conn: ConnId, l: LabelId, ids: &[BlobId], keys: &HeadKeys, out: &mut Vec<Action>) -> Result<()> {
        let mut entries = Vec::new();
        for b in ids {
            // one upload of an entry in flight per connection: a second status would reach the
            // sync records (`eph_status`)
            if self.eph.uploads.contains(&(conn, l, *b)) {
                continue;
            }
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
            self.eph.uploads.insert((conn, l, *b));
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
            let lane = self.eph.uploads.remove(&(conn, l, b)) || (self.eph.entries.contains_key(&(l, b)) && !self.state.entries.contains_key(&(l, b)));
            if !lane {
                rest.0.push(b);
                rest.1.push(code);
                continue;
            }
            if !self.eph.entries.contains_key(&(l, b)) {
                // a relay-only entry, or one forgotten meanwhile
                continue;
            }
            match code {
                Code::OK => {
                    self.eph.present.insert((server, l, b));
                }
                Code::STORAGE_CAP => {
                    self.eph.server_full.insert(l);
                    if self.eph.entries.get(&(l, b)).is_some_and(|e| e.own && self.engine.ephemeral_is_cover(&e.commit)) {
                        self.eph.own_full.entry(l).or_default().insert(server);
                    }
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
    /// upload; `from` where it came from): kept, applied and spread once the engine verified and
    /// holds its commit; one waiting for its author's record kept apart, unspread; a relay-only
    /// one delivered and passed on (`relay_in`).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn eph_added(&mut self, from: RelayFrom, l: LabelId, b: BlobId, blob: Vec<u8>, wrap: [u8; osis_crypto::WRAP_LEN], stamp: Option<Signature>, class: Class, out: &mut Vec<Action>) -> Result<()> {
        if class == Class::Relay {
            return self.relay_in(from, l, b, blob, wrap, stamp, out);
        }
        let server = from.server();
        // the one routing point: a blob whose prefix says ephemeral is the lane's, whatever an
        // announcement without its bytes made the durable path record (spec/sync.md §4)
        if self.state.entries.contains_key(&(l, b)) {
            self.state.forget_ephemeral(l, b);
        }
        if self.eph.entries.contains_key(&(l, b)) || self.eph.pending.contains_key(&(l, b)) {
            if let Some(s) = server {
                self.eph.present.insert((s, l, b));
            }
            return Ok(());
        }
        let Some(g) = self.group_of(&l) else { return Ok(()) };
        let secrets = self.read_secrets(&g);
        let Some((_, key)) = osis_label::unwrap_any(secrets.iter(), &b, &wrap) else { return Ok(()) };
        let (pt, cb) = match open_commit(&blob, &key) {
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
        let first = osis_commit::CommitBlob::decode(&pt).ok().and_then(|c| c.parts.first().map(|p| p.ai)).unwrap_or(0);
        let ingested = self.engine.ingest_ephemeral(cb);
        let salt = osis_label::Prefix::parse(&blob).map(|p| *p.salt()).unwrap_or_default();
        let a = h.aspects.get(first);
        let keys = a.map(|a| a.keys.iter().filter_map(|i| h.keys.get(*i).copied()).collect()).unwrap_or_default();
        let e = LaneEntry { commit, blob, wrap, stamp, own: false, salt, blind: h.blind, tid: a.map_or(g, |a| a.tid), actor: h.actor, keys };
        match ingested {
            Ok(EphIngest::Held { .. }) if self.engine.holds_ephemeral(&commit) => {}
            Ok(EphIngest::Pending) => {
                // unverified: kept apart under a share of the cap, neither served nor spread
                let p = self.eph.pending_bytes.get(&l).copied().unwrap_or(0);
                if p.saturating_add(size) > self.cfg.ephemeral_bytes / PENDING_SHARE {
                    self.engine.forget_pending_ephemeral(&commit);
                    if self.eph.refused.insert(l) {
                        self.eph_report(&l, "this node's share for ephemeral commits by unknown authors was reached: further ones are not kept");
                    }
                    return Ok(());
                }
                *self.eph.pending_bytes.entry(l).or_default() += size;
                if let Some(s) = server {
                    self.eph.present.insert((s, l, b));
                }
                self.eph.pending.insert((l, b), (e, server));
                return Ok(());
            }
            Ok(EphIngest::Dropped { absorbed: true }) => {
                // a replay of a covered entry: a writer deletes it where it found it
                if let Some(s) = server {
                    self.eph_delete_at(s, l, b, &e, out)?;
                }
                return Ok(());
            }
            Ok(_) => return Ok(()),
            Err(err) => {
                self.diag(format!("ephemeral commit {commit:?}: {err}"));
                return Ok(());
            }
        }
        if let Some(s) = server {
            self.eph.present.insert((s, l, b));
        }
        self.eph_keep(l, b, e);
        if stamp.is_some() {
            self.eph_spread(l, b, server, out)?;
        }
        Ok(())
    }

    /// Deletes ephemeral entry `b` of `l` at server `s` where this node may (a writer: the
    /// part's level-3 delete key and the label's write key, spec/sync.md §5).
    fn eph_delete_at(&mut self, s: ServerKey, l: LabelId, b: BlobId, e: &LaneEntry, out: &mut Vec<Action>) -> Result<()> {
        let dks = self.engine.ephemeral_delete_secrets_for(&e.tid, &e.actor, &e.keys);
        for (conn, server, hk) in self.eph_conns(&l) {
            if server != s || self.eph.deletes.contains(&(conn, l, b)) {
                continue;
            }
            if let Some(item) = delete_item(&hk, &l, b, None, Some((&e.salt, &e.blind)), &dks) {
                self.eph.deletes.insert((conn, l, b));
                self.command(conn, Command::Delete { label: l, items: vec![item] }, out)?;
            }
        }
        Ok(())
    }

    /// A relay-only entry (a push, a fetch, a served session's upload; `from` where it came
    /// from): dropped unopened when too large, outside its prefix window or seen before
    /// (`RelaySeen`); else verified and its signals delivered once, then passed on as a server
    /// would: to the sessions this node serves, and, from one of them, to the servers it syncs the
    /// label with (spec/sync.md §5, §9).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn relay_in(&mut self, from: RelayFrom, l: LabelId, b: BlobId, blob: Vec<u8>, wrap: [u8; osis_crypto::WRAP_LEN], stamp: Option<Signature>, out: &mut Vec<Action>) -> Result<()> {
        if blob.len() > osis_base::format::MAX_RELAY_BLOB {
            return Ok(());
        }
        let Some(t) = osis_label::Prefix::parse(&blob).ok().and_then(|p| p.expiry()).map(|t| t.0) else { return Ok(()) };
        let now = self.now();
        if t <= now || t > now.saturating_add(2 * osis_base::format::MAX_DRIFT_MS) || !self.eph.relays.fresh(l, b, t, now) {
            return Ok(());
        }
        let Some(g) = self.group_of(&l) else { return Ok(()) };
        let secrets = self.read_secrets(&g);
        let Some((_, key)) = osis_label::unwrap_any(secrets.iter(), &b, &wrap) else { return Ok(()) };
        let (_, cb) = match open_commit(&blob, &key) {
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
        match self.engine.ingest_ephemeral(cb) {
            Ok(EphIngest::Relayed { .. }) => self.eph.relays.record(l, b, t),
            Ok(_) => return Ok(()),
            Err(e) => {
                self.diag(format!("relay-only commit {id:?}: {e}"));
                return Ok(());
            }
        }
        let Some(stamp) = stamp else { return Ok(()) };
        let r = osis_proto::Relayed { label: l, blob_id: b, blob, wrap, stamp };
        if !self.served.is_empty() {
            let labels = self.served_labels();
            let conns: Vec<ConnId> = self.served.keys().copied().filter(|c| from != RelayFrom::Served(*c)).collect();
            for c in conns {
                self.serve_with(c, osis_proto::ServerInput::Relay(r.clone()), &labels, out)?;
            }
        }
        if let RelayFrom::Served(_) = from {
            for (conn, _, _) in self.eph_conns(&l) {
                self.eph.uploads.insert((conn, l, b));
                self.command(conn, Command::Upload { label: l, entries: vec![osis_proto::Entry { blob: r.blob.clone(), wrap: r.wrap, stamp: r.stamp }] }, out)?;
            }
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
                self.eph.by_blob.remove(&(b, l));
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
                        self.eph.deletes.insert((conn, l, b));
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
        self.eph.reconciling.retain(|(c, _)| *c != conn);
        self.eph.uploads.retain(|(c, _, _)| *c != conn);
        self.eph.deletes.retain(|(c, _, _)| *c != conn);
    }

    /// Statuses of lane deletes are taken out; the rest are returned for the durable path.
    pub(crate) fn eph_delete_status(&mut self, conn: ConnId, l: LabelId, ids: Vec<BlobId>, codes: Vec<Code>) -> (Vec<BlobId>, Vec<Code>) {
        ids.into_iter().zip(codes).filter(|(b, _)| !self.eph.deletes.remove(&(conn, l, *b))).unzip()
    }

    /// Ephemeral entries held under `l` (serving peers): ID and entry.
    pub(crate) fn eph_entries_of<'a>(lane: &'a Lane, l: &LabelId) -> impl Iterator<Item = (BlobId, &'a LaneEntry)> {
        let l = *l;
        lane.entries.range((l, BlobId([0; 32]))..).take_while(move |((x, _), _)| *x == l).map(|((_, b), e)| (*b, e))
    }

    /// Tests: compacts every held ephemeral aspect this node may write now (forced) and sends
    /// the cover as `eph_step` would.
    #[doc(hidden)]
    pub fn compact_ephemeral_now(&mut self) -> Result<Vec<Action>> {
        let mut out = Vec::new();
        if let Some(c) = self.engine.compact_ephemeral(None, true)? {
            let dropped = self.engine.take_dropped_ephemeral();
            self.eph_forget(&dropped, &mut out)?;
            self.eph_place(c, &mut out)?;
        }
        Ok(out)
    }

    /// Ephemeral bytes held from others under `l` (tests, diagnostics).
    pub fn ephemeral_bytes(&self, l: &LabelId) -> u64 {
        self.eph.bytes.get(l).copied().unwrap_or(0)
    }

    /// Bytes of entries under `l` waiting for their author's record (tests, diagnostics).
    pub fn ephemeral_pending_bytes(&self, l: &LabelId) -> u64 {
        self.eph.pending_bytes.get(l).copied().unwrap_or(0)
    }

    /// Ephemeral entries held under `l` (tests, diagnostics).
    pub fn ephemeral_entries(&self, l: &LabelId) -> usize {
        Self::eph_entries_of(&self.eph, l).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(n: u32) -> BlobId {
        let mut x = [0u8; 32];
        x[..4].copy_from_slice(&n.to_le_bytes());
        BlobId(x)
    }

    // spec/sync.md §9 (relay-only entries remembered, a floor past the bound; security review
    // L1): a repeat is dropped; past the bound the earliest-expiring entry is forgotten and its
    // label refuses everything expiring at or before it, so a forgotten one never comes back
    #[test]
    fn relay_seen_once_past_the_bound_spec_sync_9() {
        let mut r = RelaySeen::default();
        let (l, other) = (LabelId([1; 16]), LabelId([2; 16]));
        let now = 1_000_000;
        assert!(r.first(l, b(0), now + 10, now));
        assert!(!r.first(l, b(0), now + 10, now), "a repeat");
        for n in 1..=RELAYS_REMEMBERED as u32 {
            assert!(r.first(l, b(n), now + 10 + u64::from(n), now));
        }
        assert!(!r.first(l, b(0), now + 10, now), "forgotten, under the floor: still not twice");
        assert!(r.first(other, b(0), now + 10, now), "the floor is per label");
        assert!(r.first(l, b(RELAYS_REMEMBERED as u32 + 1), now + 20 + RELAYS_REMEMBERED as u64, now));
        // past their expiry entries and floors go
        assert!(r.first(l, b(7), now + 1_000_000_000, now + 500_000_000));
        assert_eq!(r.ids.len(), 1);
        assert!(r.floor.is_empty());
    }
}
