//! The pass at one server for one label after its log was read to the end (spec/sync.md §5-§7;
//! spec/permissions.md §4): re-registration first when this admin holds newer epochs than the
//! head (the actor's membership commits the server lacks, then the step; the rest after it is
//! registered), then uploads of must-hold bodies (membership first) or relays of stamped ones,
//! this node's certificates and node card, heartbeats, and deletions of must-not-hold bodies
//! (by delete key or token, carriers first), timed deletes for relative keep-at-most.

use super::state::{BlobRec, Entry, Kind, ServerKey};
use super::{ConnId, SyncEngine};
use crate::error::Result;
use crate::labeling::{Body, Facts, HeadKeys, Hold, Why, classify, delete_item, may_delete, seal_body};
use osis_commit::Kind as CKind;
use osis_core::format::HEARTBEAT_MIN_INTERVAL_MS;
use osis_core::{Ak, BlobId, CommitId, LabelId, Role, Tid, WallMs};
use osis_crypto::Secret32;
use osis_proto::Command;
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};

/// A node's verdicts on one label at one server (`SyncEngine::verdicts`).
#[derive(Clone, Debug, Default)]
pub struct Verdicts {
    /// It stamps here (uploads what it judges must-hold).
    pub writer: bool,
    /// Bodies it judges must-hold: (commit, the delta parts no snapshot under the label covers).
    /// A live entry of the commit holding those parts holds the body.
    pub must_hold: Vec<(CommitId, Vec<(usize, usize)>)>,
    /// Entries it knows under the label that it judges must-not-hold and may delete now with a
    /// delete item it can make: (blob, why).
    pub must_not: Vec<(BlobId, String)>,
    /// Aspects it cannot judge coverage of yet (`None`: every aspect, an entry opens but is not
    /// applied).
    pub unsettled: Vec<Option<(Tid, Ak)>>,
}

/// An entry to send, by priority (membership and certificates before content before
/// heartbeats).
struct Out {
    prio: u8,
    id: BlobId,
}

/// A judged entry: the rule's answer, whether it may carry live writes, its aspects.
type Judged = (Hold, bool, Vec<(Tid, Ak)>);

fn is_snapshot(k: CKind) -> bool {
    matches!(k, CKind::ContentSnapshot | CKind::MembershipSnapshot)
}

impl SyncEngine {
    pub(crate) fn pass(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(c) = self.conns.get(&conn) else { return Ok(()) };
        let server = c.server;
        let Some(lc) = c.labels.get(&l) else { return Ok(()) };
        let (g, head, index) = (lc.group, lc.head.clone(), lc.index.unwrap_or(0));
        // secrets may have arrived since the head was accepted
        let mut keys = match &head {
            Some(h) => self.engine.head_keys(&g, index, h)?,
            None => return Ok(()),
        };
        // never encrypt under an epoch that does not cover a known departure: rotate first
        // (flows' cascade), else hold back what the uncovered roles would sign or wrap
        let still = self.uncovered(&g)?;
        if still.contains(&Role::Write) {
            keys.write = None;
        }
        if still.contains(&Role::Admin) {
            keys.delete = None;
        }
        let read_ok = !still.contains(&Role::Read);
        if !read_ok {
            keys.sync_established = false;
        }
        if let Some(lc) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&l)) {
            lc.keys = keys.clone();
        }
        // a complete pass and still no secret of the head's read epoch: stranded
        if keys.epochs[0].is_none() {
            return self.stranded(conn, g, l, out);
        }
        if self.reregister(conn, l, out)? {
            return Ok(());
        }
        // atomic apply waits for the closure's deltas (spec/commits.md §4)
        for t in self.engine.closure(&g) {
            if !self.engine.core.syncing.contains(&t) {
                self.engine.set_syncing(t, true)?;
            }
        }
        // content snapshots under the label: drop the bodies they cover (spec/sync.md §7)
        let snaps = self.snapshots_at(&l);
        let mut done = Vec::new();
        for ((t, a), ss) in &snaps {
            for s in ss {
                if self.snapshots_seen.contains(s) || !self.engine.core.commits.get(s).is_some_and(|m| m.header.kind == CKind::ContentSnapshot) {
                    continue;
                }
                self.drop_covered(t, a, s)?;
                done.push(*s);
            }
        }
        self.snapshots_seen.extend(done);
        self.forget_dropped()?;
        let mut bodies = self.engine.label_bodies(&g)?;
        bodies.retain(|b| !self.state.inbox_only.contains(&b.commit));
        let mut sends: Vec<Out> = Vec::new();
        let unsettled = self.unsettled(&l, &g)?;
        for b in &bodies {
            let Some(needed) = self.must_hold(b, &snaps, &unsettled)? else { continue };
            // another projection of the commit (a right holder dropped covered deltas) holds it
            if needed != b.parts && self.carried_by(&server, &l, &b.commit, &needed) {
                continue;
            }
            let entry = self.entry_for(&server, &l, b);
            let id = match entry {
                Some(id) => id,
                None if read_ok && (keys.is_writer() || self.may_deposit(&keys, b)) => match self.place(&g, l, b, false)? {
                    Some(id) => id,
                    None => continue,
                },
                None => continue,
            };
            let prio = if self.first.contains(&b.commit) {
                0
            } else if b.membership {
                1
            } else {
                3
            };
            sends.push(Out { prio, id });
            if keys.is_writer() {
                for cb in self.chunk_blobs(&b.commit)? {
                    if !self.state.entries.contains_key(&(l, cb)) {
                        let wrap = osis_crypto::filler_wrap(&mut *self.rng);
                        self.state.set_entry(l, cb, Entry { wrap, stamp: None, cert: false, kind: Kind::Unknown });
                    }
                    sends.push(Out { prio, id: cb });
                }
            }
        }
        if read_ok && (keys.is_writer() || keys.deposit.is_some()) {
            self.certificates(&g, l)?;
            self.heartbeat(&g, l, &keys, conn)?;
        }
        // every certificate copy this node placed here: chain, card, flows' placements
        let certs: Vec<(BlobId, Option<CommitId>)> = self
            .state
            .entries
            .range((l, BlobId([0; 32]))..)
            .take_while(|((x, _), _)| *x == l)
            .filter(|(_, e)| e.cert)
            .map(|((_, id), e)| (*id, if let Kind::Commit { commit, .. } = &e.kind { Some(*commit) } else { None }))
            .collect();
        for (id, c) in certs {
            let beat = c.and_then(|c| self.engine.header(&c)).is_some_and(|h| h.aspects.iter().any(|a| a.ak.as_str() == "/seen"));
            let prio = if c.is_some_and(|c| self.first.contains(&c)) {
                0
            } else if beat {
                4
            } else {
                2
            };
            sends.push(Out { prio, id });
        }
        sends.sort_by_key(|o| o.prio);
        let mut seen = BTreeSet::new();
        let mut uploads = Vec::new();
        let mut deposits = Vec::new();
        for o in sends {
            if !seen.insert(o.id) || self.state.is_present(&server, &l, &o.id) || self.state.gone.contains(&(server, l, o.id)) {
                continue;
            }
            let Some(e) = self.state.entries.get(&(l, o.id)).cloned() else { continue };
            let Some(blob) = self.engine.blob(&o.id)? else { continue };
            if let Some(w) = &keys.write {
                let stamp = osis_label::sign_stamp(w, &l, &o.id, &e.wrap);
                uploads.push(osis_proto::Entry { blob, wrap: e.wrap, stamp });
                // kept, so a later pass does not promote it again
                let mut e = e;
                e.stamp = Some(stamp);
                self.state.set_entry(l, o.id, e);
            } else if let Some(stamp) = e.stamp {
                uploads.push(osis_proto::Entry { blob, wrap: e.wrap, stamp });
            } else if let Some(d) = &keys.deposit
                && self.mine(&e)
            {
                let sig = osis_label::sign_deposit(d, &l, &o.id, &e.wrap);
                deposits.push((blob, e.wrap, sig));
            }
        }
        if let Some(w) = &keys.write {
            self.promote(server, l, w, &mut uploads)?;
        }
        if !uploads.is_empty() {
            self.command(conn, Command::Upload { label: l, entries: uploads }, out)?;
        }
        for (blob, wrap, sig) in deposits {
            self.command(conn, Command::Deposit { label: l, blob, wrap, sig }, out)?;
        }
        let settled = unsettled.is_empty();
        self.deletions(conn, server, l, &g, &keys, &bodies, &snaps, settled, out)
    }

    /// This node's verdicts on label `l` at `server` under the keys its last pass there used
    /// (simulator invariants, spec/sync.md §6); `None` when the label is not open there.
    pub fn verdicts(&mut self, server: &ServerKey, l: &LabelId) -> Result<Option<Verdicts>> {
        let Some(lc) = self.conns.values().filter(|c| c.server == *server).find_map(|c| c.labels.get(l).filter(|x| x.phase == super::Phase::Open)) else { return Ok(None) };
        let (g, keys) = (lc.group, lc.keys.clone());
        let mut v = Verdicts { writer: keys.is_writer(), ..Verdicts::default() };
        let mut bodies = self.engine.label_bodies(&g)?;
        bodies.retain(|b| !self.state.inbox_only.contains(&b.commit));
        let snaps = self.snapshots_at(l);
        let unsettled = self.unsettled(l, &g)?;
        v.unsettled = unsettled.iter().cloned().collect();
        for b in &bodies {
            if let Some(needed) = self.must_hold(b, &snaps, &unsettled)? {
                v.must_hold.push((b.commit, needed));
            }
        }
        let entries: Vec<(BlobId, Entry)> = self.state.entries.range((*l, BlobId([0; 32]))..).take_while(|((x, _), _)| x == l).map(|((_, b), e)| (*b, e.clone())).collect();
        for (id, e) in entries {
            let Some((Hold::MustNot(why), live, aspects)) = self.judge(server, l, &g, &id, &e, &bodies, unsettled.is_empty())? else { continue };
            let carried = match why {
                Why::Duplicate | Why::StrictSubset => true,
                _ => self.carried(server, l, &e, &aspects, &snaps)?,
            };
            if why != Why::Expired && may_delete(why, live, carried) && self.delete_for(&keys, l, &id, &e, None)?.is_some() {
                v.must_not.push((id, format!("{why:?}")));
            }
        }
        Ok(Some(v))
    }

    /// Aspects this node cannot judge coverage of yet: those of pending commits; every aspect
    /// (`None` in the set) while an entry of the label opens under a held secret and is not
    /// applied (a snapshot not fetched or applied yet, spec/sync.md §6: may-hold).
    fn unsettled(&mut self, l: &LabelId, g: &Tid) -> Result<BTreeSet<Option<(Tid, Ak)>>> {
        let mut out = BTreeSet::new();
        for (c, r) in self.engine.pending() {
            if r == crate::Reason::Parked {
                continue;
            }
            let Some(bytes) = self.engine.commit_bytes(&c)? else { continue };
            if let Ok(cb) = osis_commit::CommitBlob::decode(&bytes) {
                out.extend(cb.header.aspects.iter().map(|a| Some((a.tid, a.ak.clone()))));
            }
        }
        let secrets = self.read_secrets(g);
        let unopened = self.state.entries.range((*l, BlobId([0; 32]))..).take_while(|((x, _), _)| x == l).any(|((_, b), e)| e.kind == Kind::Unknown && osis_label::unwrap_any(secrets.iter(), b, &e.wrap).is_some());
        if unopened {
            out.insert(None);
        }
        Ok(out)
    }

    /// A writer re-uploads stamped the deposited entries it verified (spec/sync.md §5): applied
    /// commits, never a heartbeat; per server (a blob may be deposited at several).
    fn promote(&mut self, server: ServerKey, l: LabelId, write: &osis_crypto::SigningSecret, uploads: &mut Vec<osis_proto::Entry>) -> Result<()> {
        let ids: Vec<(BlobId, Entry)> = self
            .state
            .entries
            .range((l, BlobId([0; 32]))..)
            .take_while(|((x, _), _)| *x == l)
            .filter(|((_, b), _)| self.state.deposited.contains(&(server, l, *b)))
            .map(|((_, b), e)| (*b, e.clone()))
            .collect();
        for (id, mut e) in ids {
            let Kind::Commit { commit, .. } = &e.kind else { continue };
            let Some(h) = self.engine.header(commit) else { continue };
            if h.aspects.iter().any(|a| a.ak.as_str() == "/seen") || uploads.iter().any(|u| osis_label::blob_id(&u.blob) == id) {
                continue;
            }
            let Some(blob) = self.engine.blob(&id)? else { continue };
            let stamp = osis_label::sign_stamp(write, &l, &id, &e.wrap);
            uploads.push(osis_proto::Entry { blob, wrap: e.wrap, stamp });
            e.stamp = Some(stamp);
            self.state.set_entry(l, id, e);
            self.state.set_deposited(server, l, id, false);
        }
        Ok(())
    }

    /// Whether this node placed the entry (its certificates, heartbeats, membership writes).
    fn mine(&self, e: &Entry) -> bool {
        e.cert || matches!(&e.kind, Kind::Commit { commit, .. } if self.engine.header(commit).is_some_and(|h| h.author == self.engine.tid()))
    }

    /// A non-writer deposits its own membership writes (an invite grant, a self-removal,
    /// spec/sync.md §3).
    fn may_deposit(&self, keys: &HeadKeys, b: &Body) -> bool {
        keys.deposit.is_some() && b.membership && self.engine.header(&b.commit).is_some_and(|h| h.author == self.engine.tid())
    }

    /// Snapshot commits under the label, by aspect.
    fn snapshots_at(&self, l: &LabelId) -> BTreeMap<(Tid, Ak), Vec<CommitId>> {
        let mut m: BTreeMap<(Tid, Ak), Vec<CommitId>> = BTreeMap::new();
        for ((x, _), e) in self.state.entries.range((*l, BlobId([0; 32]))..) {
            if x != l {
                break;
            }
            let Kind::Commit { commit, .. } = &e.kind else { continue };
            let Some(h) = self.engine.header(commit) else { continue };
            if is_snapshot(h.kind) {
                for a in &h.aspects {
                    m.entry((a.tid, a.ak.clone())).or_default().push(*commit);
                }
            }
        }
        m
    }

    /// Must-hold for a closure body (spec/sync.md §6): before its keep-at-least bound, or
    /// established uncovered by the label's snapshots. Must-hold: the parts a blob of the commit
    /// must hold to hold the body (all of them before keep-at-least, else those of the aspects
    /// no snapshot covers).
    fn must_hold(&mut self, b: &Body, snaps: &BTreeMap<(Tid, Ak), Vec<CommitId>>, unsettled: &BTreeSet<Option<(Tid, Ak)>>) -> Result<Option<Vec<(usize, usize)>>> {
        let Some(h) = self.engine.header(&b.commit) else { return Ok(None) };
        let aspects: Vec<(Tid, Ak)> = b.parts.iter().filter_map(|(ai, _)| h.aspects.get(*ai)).map(|a| (a.tid, a.ak.clone())).collect();
        let now = self.now();
        let mut before = false;
        if let Some((t, a)) = aspects.first() {
            before = self.engine.body_keep(&b.commit, t, a)?.at_least > now;
        }
        let mut covered = !aspects.is_empty();
        let mut needed = Vec::new();
        for (p, (t, a)) in b.parts.iter().zip(&aspects) {
            let mut c = false;
            for s in snaps.get(&(*t, a.clone())).into_iter().flatten() {
                if *s != b.commit && self.engine.covered(s, &b.commit, t, a)? == Some(true) {
                    // covered-equal snapshots: the one with the higher commit ID goes
                    if is_snapshot(h.kind) && self.engine.covered(&b.commit, s, t, a)? == Some(true) && b.commit < *s {
                        continue;
                    }
                    c = true;
                    break;
                }
            }
            covered &= c;
            if before || !c {
                needed.push(*p);
            }
        }
        let known = !unsettled.contains(&None) && !aspects.iter().any(|k| unsettled.contains(&Some(k.clone())));
        let covered = if covered || known { Some(covered) } else { None };
        let must = classify(&Facts { required: true, closure: true, before_at_least: before, covered, ..Facts::default() }) == Hold::Must;
        Ok(must.then_some(needed))
    }

    /// Whether an entry of commit `c` holding `parts` is present at `server` under `l`.
    fn carried_by(&self, server: &ServerKey, l: &LabelId, c: &CommitId, parts: &[(usize, usize)]) -> bool {
        self.state
            .entries
            .range((*l, BlobId([0; 32]))..)
            .take_while(|((x, _), _)| x == l)
            .any(|((_, id), e)| !e.cert && matches!(&e.kind, Kind::Commit { commit, parts: p } if commit == c && parts.iter().all(|x| p.contains(x))) && self.state.is_present(server, l, id))
    }

    /// The entry under `l` holding exactly this body, not tombstoned at `server`, whoever
    /// placed it (a certificate copy of the same parts holds it too: other nodes see one entry).
    fn entry_for(&self, server: &ServerKey, l: &LabelId, b: &Body) -> Option<BlobId> {
        self.state
            .entries
            .range((*l, BlobId([0; 32]))..)
            .take_while(|((x, _), _)| x == l)
            .filter(|((_, id), e)| matches!(&e.kind, Kind::Commit { commit, parts } if *commit == b.commit && *parts == b.parts) && !self.state.gone.contains(&(*server, *l, *id)))
            .map(|((_, id), _)| *id)
            .min()
    }

    /// Places a body under `l`: an encryption of it this node holds (never a certificate
    /// copy's, never one tombstoned there), else a fresh one; wrapped for the label.
    fn place(&mut self, g: &Tid, l: LabelId, b: &Body, cert: bool) -> Result<Option<BlobId>> {
        let Some(secret) = self.engine.wrap_secret(g, Some((&b.commit, &b.parts)))? else { return Ok(None) };
        let reuse = if cert { None } else { self.state.blob_for(&b.commit, &b.parts, |id| self.state.is_gone(&l, id) || self.state.entries.contains_key(&(l, *id))) };
        let (id, key) = match reuse.and_then(|id| self.state.blobs.get(&id).map(|r| (id, r.key.clone()))) {
            Some(x) => x,
            None => {
                let s = seal_body(b, &mut *self.rng)?;
                self.engine.put_blobs(vec![(s.id, s.blob)])?;
                self.state.add_blob(s.id, BlobRec { commit: b.commit, parts: b.parts.clone(), key: s.key.clone(), cert });
                (s.id, s.key)
            }
        };
        let wrap = osis_crypto::wrap(&secret, &id, &key)?;
        self.state.set_entry(l, id, Entry { wrap, stamp: None, cert, kind: Kind::Commit { commit: b.commit, parts: b.parts.clone() } });
        Ok(Some(id))
    }

    /// Chunk, page and header-list blobs a commit references that this node holds.
    fn chunk_blobs(&mut self, c: &CommitId) -> Result<Vec<BlobId>> {
        Ok(self.engine.package(c)?.map(|p| p.blobs.into_iter().map(|(id, _)| id).collect()).unwrap_or_default())
    }

    /// This node's chain certificates and node card under `l` (spec/permissions.md §4): a fresh
    /// encryption per label, placed once per commit.
    fn certificates(&mut self, g: &Tid, l: LabelId) -> Result<()> {
        for (c, ais) in self.engine.certificates(g) {
            if self.state.inbox_only.contains(&c) {
                continue;
            }
            let placed: Vec<BlobId> = self
                .state
                .entries
                .range((l, BlobId([0; 32]))..)
                .take_while(|((x, _), _)| *x == l)
                .filter(|(_, e)| e.cert && matches!(&e.kind, Kind::Commit { commit, .. } if *commit == c))
                .map(|((_, id), _)| *id)
                .collect();
            if placed.is_empty() && !self.state.certs.contains(&(l, c)) {
                for b in self.engine.partial_bodies(&c, &ais)? {
                    self.place(g, l, &b, true)?;
                }
                self.state.add_cert(l, c);
            }
        }
        Ok(())
    }

    /// A heartbeat under `l` at most once per `HEARTBEAT_MIN_INTERVAL` (spec/permissions.md §4),
    /// skipped by deposit when the budget is tight.
    fn heartbeat(&mut self, g: &Tid, l: LabelId, keys: &HeadKeys, conn: ConnId) -> Result<()> {
        if !self.cfg.heartbeats {
            return Ok(());
        }
        let now = self.now();
        if self.state.beats.get(&l).is_some_and(|t| t.saturating_add(HEARTBEAT_MIN_INTERVAL_MS) > now) {
            return Ok(());
        }
        let tight = self.conns.get(&conn).and_then(|c| c.labels.get(&l)).and_then(|x| x.budget).is_some_and(|b| b < self.cfg.tight_budget);
        if !keys.is_writer() && tight {
            return Ok(());
        }
        let Some(c) = self.heartbeat_commit(false)? else { return Ok(()) };
        let ais = BTreeSet::from([0usize]);
        for b in self.engine.partial_bodies(&c, &ais)? {
            self.place(g, l, &b, true)?;
        }
        self.state.set_beat(l, now);
        Ok(())
    }

    /// A `/seen` commit on this node (spec/permissions.md §4): reused within the interval.
    pub(crate) fn heartbeat_commit(&mut self, stranded: bool) -> Result<Option<CommitId>> {
        let me = self.engine.tid();
        let now = self.now();
        if !stranded
            && let Some(c) = self.engine.core.by_aspect.get(&(me, Ak::new("/seen").map_err(|_| crate::Error::Misuse("ak"))?)).and_then(|s| s.iter().next_back()).map(|x| x.1)
            && let Some(h) = self.engine.header(&c)
            && h.ts.wall_ms().0.saturating_add(HEARTBEAT_MIN_INTERVAL_MS) > now
            && self.engine.get_typed(&me, &ct::SEEN)?.is_some_and(|s| !s.stranded)
        {
            return Ok(Some(c));
        }
        // `ts` of the commit: the HLC's next wall time (spec/permissions.md §4)
        let ts = now.max(self.engine.core.hlc.last().wall_ms().0);
        let life = self.cfg.heartbeat_lifetime_ms.clamp(osis_core::format::HEARTBEAT_MIN_LIFETIME_MS, osis_core::format::HEARTBEAT_MAX_LIFETIME_MS);
        let mut m = crate::Mutation::new();
        m.set(me, &ct::SEEN, &ct::Seen { ts: WallMs(ts), stranded })?;
        m.expires(me, &ct::SEEN, WallMs(ts.saturating_add(life)))?;
        self.engine.commit(m)
    }

    /// A stranded heartbeat (spec/permissions.md §4; spec/sync.md §5): the label cannot be read
    /// here; deposited, wrapped under the newest established read secret held, no open needed.
    pub(crate) fn stranded(&mut self, conn: ConnId, g: Tid, l: LabelId, out: &mut Vec<super::Action>) -> Result<()> {
        if self.stranded_at.get(&l).is_some_and(|t| t.saturating_add(HEARTBEAT_MIN_INTERVAL_MS) > self.now()) {
            return Ok(());
        }
        let Some(secret) = self.engine.stranded_secret(&g) else { return Ok(()) };
        let Some(seed) = self.engine.deposit_seed(&g)? else { return Ok(()) };
        let Some(c) = self.heartbeat_commit(true)? else { return Ok(()) };
        for b in self.engine.partial_bodies(&c, &BTreeSet::from([0usize]))? {
            let s = seal_body(&b, &mut *self.rng)?;
            let wrap = osis_crypto::wrap(&secret, &s.id, &s.key)?;
            let d = osis_crypto::deposit_key(&seed, &l);
            let sig = osis_label::sign_deposit(&d, &l, &s.id, &wrap);
            self.command(conn, Command::Deposit { label: l, blob: s.blob, wrap, sig }, out)?;
        }
        let now = self.now();
        self.stranded_at.insert(l, now);
        Ok(())
    }

    /// Re-registration (spec/sync.md §5): an admin holding the head's epochs and a newer
    /// established one uploads the actor's membership commits the server lacks under the head's
    /// keys, then registers a child step; the rest of the pass runs once it is registered.
    fn reregister(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<super::Action>) -> Result<bool> {
        let Some(c) = self.conns.get(&conn) else { return Ok(false) };
        let server = c.server;
        let Some(lc) = c.labels.get(&l) else { return Ok(false) };
        let (g, keys, head) = (lc.group, lc.keys.clone(), lc.head.clone());
        let (Some(_), Some(write), Some(head)) = (keys.delete.clone(), keys.write.clone(), head) else { return Ok(false) };
        let Some(e) = self.engine.epochs(&g) else { return Ok(false) };
        if !osis_keys::newer_than_head(&e, keys.epochs) {
            return Ok(false);
        }
        let a = self.engine.core.secret_actor(&g).unwrap_or(g);
        let ids: Vec<CommitId> = self.engine.core.commits.iter().filter(|(id, m)| m.header.kind.is_membership() && m.header.aspects.iter().any(|x| x.tid == a) && !self.state.inbox_only.contains(id)).map(|(id, _)| *id).collect();
        let mut uploads = Vec::new();
        for id in ids {
            for b in self.engine.bodies(&id)? {
                if b.reader != a && !self.engine.core.may_read(&a, &b.reader) {
                    continue;
                }
                let bid = match self.entry_for(&server, &l, &b) {
                    Some(x) => x,
                    None => match self.place(&g, l, &b, false)? {
                        Some(x) => x,
                        None => continue,
                    },
                };
                if self.state.is_present(&server, &l, &bid) {
                    continue;
                }
                let (Some(en), Some(blob)) = (self.state.entries.get(&(l, bid)).cloned(), self.engine.blob(&bid)?) else { continue };
                let stamp = osis_label::sign_stamp(&write, &l, &bid, &en.wrap);
                uploads.push(osis_proto::Entry { blob, wrap: en.wrap, stamp });
            }
        }
        if !uploads.is_empty() {
            self.command(conn, Command::Upload { label: l, entries: uploads }, out)?;
        }
        let (step, done) = self.engine.issue_step(&g, &l, &head.id(), false)?;
        self.take_done(done)?;
        let Some((step, set)) = step else { return Ok(false) };
        if let Some(lc) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&l)) {
            lc.registering = Some((step.clone(), set.clone()));
        }
        self.command(conn, Command::Register { label: l, step, claim_set: Some(set) }, out)?;
        Ok(true)
    }

    /// Facts about an entry under the label (spec/sync.md §6): `None` when this node cannot
    /// judge it (may-hold).
    #[allow(clippy::too_many_arguments)]
    fn judge(&mut self, server: &ServerKey, l: &LabelId, g: &Tid, id: &BlobId, e: &Entry, bodies: &[Body], settled: bool) -> Result<Option<Judged>> {
        let now = self.now();
        let Kind::Commit { commit, parts } = &e.kind else { return Ok(None) };
        let Some(m) = self.engine.core.commits.get(commit).cloned() else { return Ok(None) };
        let h = m.header.clone();
        // a blob expires whole with its class (spec/sync.md §3)
        if parts.first().and_then(|(ai, _)| h.aspects.get(*ai)).and_then(|a| a.expires).is_some_and(|t| t <= now) {
            return Ok(Some((Hold::MustNot(Why::Expired), false, Vec::new())));
        }
        let aspects: Vec<(Tid, Ak)> = parts.iter().filter_map(|(ai, _)| h.aspects.get(*ai)).map(|a| (a.tid, a.ak.clone())).collect();
        let dropped: Vec<(usize, usize)> = parts.iter().filter(|p| m.dropped.contains(p)).copied().collect();
        if !dropped.is_empty() {
            let live = dropped.iter().any(|(ai, _)| {
                let Some(a) = h.aspects.get(*ai) else { return false };
                let o = crate::engine::Owned::of(&h, commit, *ai);
                !self.engine.core.valueless.get(&(a.tid, a.ak.clone())).is_some_and(|v| o.as_ref().is_some_and(|o| v.contains(o)))
            });
            return Ok(Some((Hold::MustNot(Why::Dropped), live, aspects)));
        }
        if e.cert {
            return Ok(Some((Hold::May, false, aspects)));
        }
        let desired: Vec<&Vec<(usize, usize)>> = bodies.iter().filter(|b| b.commit == *commit).map(|b| &b.parts).collect();
        let mut f = Facts { required: false, closure: true, covered: None, ..Facts::default() };
        if desired.contains(&parts) {
            f.required = true;
            // the duplicate with the higher blob ID goes (spec/sync.md §7)
            f.duplicate_higher = self.state.entries.range((*l, BlobId([0; 32]))..(*l, *id)).any(|((x, b), o)| x == l && b != id && !o.cert && o.kind == e.kind && self.state.is_present(server, l, b));
        } else if desired.iter().any(|d| d.iter().all(|p| parts.contains(p))) {
            // a superset projection: every delta in it must be one the label's actor may read
            let x = self.engine.group_actor(g);
            let foreign = parts.iter().filter_map(|(ai, _)| h.aspects.get(*ai)).any(|a| !self.engine.core.may_read(&x, &self.engine.core.reader_of(&a.tid)));
            if foreign && settled {
                return Ok(Some((Hold::MustNot(Why::Outside), true, aspects)));
            }
            f.required = true;
        } else {
            let sup = self.state.entries.range((*l, BlobId([0; 32]))..).take_while(|((x, _), _)| x == l).any(|((_, b), o)| {
                b != id && matches!(&o.kind, Kind::Commit { commit: c2, parts: p2 } if c2 == commit && p2.len() > parts.len() && parts.iter().all(|p| p2.contains(p))) && self.state.present_anywhere(l, b)
            });
            if sup {
                f.required = true;
                f.strict_subset = true;
            } else if desired.iter().any(|d| parts.iter().all(|p| d.contains(p))) {
                // a lagging projection: the superset goes up first
                return Ok(None);
            } else {
                // certificates (membership-class, node cards, heartbeats) are not ours to judge
                let card = h.aspects.iter().all(|a| matches!(a.ak.as_str(), "/keys" | "/node" | "/reach" | "/seen" | "/created"));
                if h.kind.is_membership() || card {
                    return Ok(None);
                }
                // only deltas this node holds can be judged outside the label
                let c = *commit;
                let held: Vec<(usize, usize)> = self.engine.run(|tx| Ok(tx.get_commit(&c)?.map(|b| b.parts.iter().map(|p| (p.ai, p.di)).collect()).unwrap_or_default()))?;
                // and only once the view is settled (a peer's placement this node cannot
                // explain yet stays: a receiver keeps what a peer placed, spec/sync.md §3)
                if !parts.iter().all(|p| held.contains(p)) || !settled {
                    return Ok(None);
                }
            }
        }
        Ok(Some((classify(&f), true, aspects)))
    }

    /// Deletes must-not-hold entries present at the server, carriers first (spec/sync.md §6,
    /// §7); timed deletes for bodies under a relative keep-at-most (spec/commits.md §5).
    #[allow(clippy::too_many_arguments)]
    fn deletions(&mut self, conn: ConnId, server: ServerKey, l: LabelId, g: &Tid, keys: &HeadKeys, bodies: &[Body], snaps: &BTreeMap<(Tid, Ak), Vec<CommitId>>, settled: bool, out: &mut Vec<super::Action>) -> Result<()> {
        let ids = self.state.present_at(&server, &l);
        let mut items = Vec::new();
        for id in ids {
            let Some(e) = self.state.entries.get(&(l, id)).cloned() else { continue };
            let Some((hold, live, aspects)) = self.judge(&server, &l, g, &id, &e, bodies, settled)? else { continue };
            let Hold::MustNot(why) = hold else { continue };
            if why == Why::Expired {
                // the server drops it unattended (spec/sync.md §5)
                self.state.set_present(server, l, id, false);
                if !self.state.present_anywhere(&l, &id) {
                    self.state.remove_entry(l, id);
                    self.forget_blob(&id)?;
                }
                continue;
            }
            let carried = match why {
                Why::Duplicate | Why::StrictSubset => true,
                _ => self.carried(&server, &l, &e, &aspects, snaps)?,
            };
            if !may_delete(why, live, carried) {
                if let Kind::Commit { commit, .. } = &e.kind {
                    self.snapshot_first(&aspects, commit)?;
                }
                continue;
            }
            if let Some(item) = self.delete_for(keys, &l, &id, &e, None)? {
                items.push(item);
            }
        }
        // timed deletes: bodies under a relative keep-at-most with a known bound
        for b in bodies {
            let Some(id) = self.entry_for(&server, &l, b) else { continue };
            if !self.state.is_present(&server, &l, &id) || self.state.timed.contains(&(server, l, id)) {
                continue;
            }
            let Some(h) = self.engine.header(&b.commit) else { continue };
            let Some(a) = b.parts.first().and_then(|(ai, _)| h.aspects.get(*ai)) else { continue };
            if a.retention.at_most.rel.is_none() {
                continue;
            }
            let Some(t) = self.engine.body_keep(&b.commit, &a.tid, &a.ak)?.at_most else { continue };
            let aspects = vec![(a.tid, a.ak.clone())];
            let Some(e) = self.state.entries.get(&(l, id)).cloned() else { continue };
            if !self.carried(&server, &l, &e, &aspects, snaps)? {
                self.snapshot_first(&aspects, &b.commit)?;
                continue;
            }
            if let Some(item) = self.delete_for(keys, &l, &id, &e, Some(WallMs(t)))? {
                self.state.set_timed(server, l, id);
                items.push(item);
            }
        }
        if !items.is_empty() {
            self.command(conn, Command::Delete { label: l, items }, out)?;
        }
        Ok(())
    }

    /// Whether a later snapshot of each aspect is under the label at the server: the carrier of
    /// a body's live writes (spec/sync.md §7).
    fn carried(&mut self, server: &ServerKey, l: &LabelId, e: &Entry, aspects: &[(Tid, Ak)], snaps: &BTreeMap<(Tid, Ak), Vec<CommitId>>) -> Result<bool> {
        let Kind::Commit { commit, .. } = &e.kind else { return Ok(false) };
        let dropped = self.engine.core.commits.get(commit).is_some_and(|m| !m.dropped.is_empty());
        for (t, a) in aspects {
            // the snapshot that covered the body when it was dropped, else one covering it now
            let candidates: Vec<CommitId> = match self.state.carriers.get(commit) {
                Some(s) => vec![*s],
                None if dropped => Vec::new(),
                None => snaps.get(&(*t, a.clone())).cloned().unwrap_or_default(),
            };
            let mut ok = false;
            for s in candidates {
                if s == *commit || !self.state.entries.iter().any(|((x, b), o)| x == l && matches!(&o.kind, Kind::Commit { commit: c, .. } if *c == s) && self.state.is_present(server, l, b)) {
                    continue;
                }
                if self.state.carriers.get(commit) == Some(&s) || self.engine.covered(&s, commit, t, a)? == Some(true) {
                    ok = true;
                    break;
                }
            }
            if !ok {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// A right holder that must delete a body with live writes and finds no carrier writes a
    /// covering snapshot first when it may write the aspect (spec/sync.md §7).
    fn snapshot_first(&mut self, aspects: &[(Tid, Ak)], body: &CommitId) -> Result<()> {
        if self.state.carriers.contains_key(body) {
            return Ok(());
        }
        for (t, a) in aspects {
            if is_membership(a) || self.engine.role_on(t) < Some(Role::Write) {
                continue;
            }
            // a snapshot from this node's whole state covers every body of the aspect it applied
            if let Some(s) = self.engine.snapshot(t, a)? {
                self.state.set_carrier(*body, s);
            }
        }
        Ok(())
    }

    /// A delete item for an entry: delete key, else a token this node can derive.
    fn delete_for(&mut self, keys: &HeadKeys, l: &LabelId, id: &BlobId, e: &Entry, at: Option<WallMs>) -> Result<Option<osis_label::DeleteItem>> {
        let tokens: Vec<(u8, Secret32)> = match &e.kind {
            Kind::Commit { commit, parts } => self.engine.tokens_of(commit, parts),
            _ => Vec::new(),
        };
        Ok(delete_item(keys, l, *id, at, &tokens))
    }
}

fn is_membership(a: &Ak) -> bool {
    osis_schema::core_types::is_membership_class(a.as_str())
}
