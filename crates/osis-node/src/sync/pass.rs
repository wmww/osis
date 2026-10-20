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
        // certificate copies that waited for the rotation just run
        if read_ok {
            let (now, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.deferred).into_iter().partition(|(x, _, _)| *x == g);
            self.deferred = later;
            for (x, c, ais) in now {
                self.place_certificate_in(&x, &c, &ais)?;
            }
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
        // others' content snapshots under the label: drop the bodies they cover (spec/sync.md
        // §7; this node's own were a compaction, or a carrier written for a keep-at-most bound)
        let snaps = self.snapshots_at(&l);
        let mut done = Vec::new();
        let me = self.engine.tid();
        for ((t, a), ss) in &snaps {
            for s in ss {
                if self.snapshots_seen.contains(s) || !self.engine.core.commits.get(s).is_some_and(|m| m.header.kind == CKind::ContentSnapshot && m.header.author != me) {
                    continue;
                }
                self.drop_covered(t, a, s)?;
                done.push(*s);
            }
        }
        self.snapshots_seen.extend(done);
        self.forget_dropped()?;
        let bodies = self.bodies_under(&g, &l)?;
        let replaced = self.is_replaced(&g, &l);
        let mut sends: Vec<Out> = Vec::new();
        self.refetch(conn, server, l, &g, out)?;
        self.check_linked_prefixes(l)?;
        let unsettled = self.unsettled(&l, &g)?;
        let snapping = self.unsettled_hold(&l, &g)?;
        for b in &bodies {
            let Some(needed) = self.must_hold(b, &snaps, &snapping)? else { continue };
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
        // parked commits travel like at a blind node: stamped entries are relayed (spec/versioning.md §2)
        for ((_, id), e) in self.state.entries.range((l, BlobId([0; 32]))..).take_while(|((x, _), _)| *x == l) {
            if matches!(e.kind, Kind::Parked(_)) && e.stamp.is_some() {
                sends.push(Out { prio: 3, id: *id });
            }
        }
        if !replaced && read_ok && (keys.is_writer() || keys.deposit.is_some()) {
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
        let raw = self.raw_now();
        let mut seen = BTreeSet::new();
        let mut uploads = Vec::new();
        let mut deposits = Vec::new();
        for o in sends {
            if !seen.insert(o.id) || self.state.is_present(&server, &l, &o.id) || self.state.gone.contains(&(server, l, o.id)) || super::in_flight(&self.sent, &(conn, l, o.id), raw) {
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
            self.promote(conn, server, l, w, &mut uploads)?;
        }
        if !uploads.is_empty() {
            self.sent.extend(uploads.iter().map(|u| ((conn, l, osis_label::blob_id(&u.blob)), raw)));
            self.command(conn, Command::Upload { label: l, entries: uploads }, out)?;
        }
        for (blob, wrap, sig) in deposits {
            self.sent.insert((conn, l, osis_label::blob_id(&blob)), raw);
            self.command(conn, Command::Deposit { label: l, blob, wrap, sig }, out)?;
        }
        let settled = unsettled.is_empty();
        self.deletions(conn, server, l, &g, &keys, &bodies, &snaps, settled, out)?;
        self.reseal(&g, l)?;
        Ok(())
    }

    /// Re-seals decided at the end of a complete pass of the actor's labels (spec/permissions.md
    /// §3): members seen without a box at a current epoch (`Engine::reseal_due`) and members
    /// whose node's heartbeat under the label reports it stranded (§4); delivered by inbox and
    /// placed under the actor's labels like any membership commit.
    fn reseal(&mut self, g: &Tid, l: LabelId) -> Result<()> {
        let Some(a) = self.engine.core.secret_actor(g) else { return Ok(()) };
        if self.engine.core.is_key_actor(&a) || !self.complete_pass(&a) {
            return Ok(());
        }
        // the complete pass was checked just above
        struct Passed;
        impl crate::flows::SyncState for Passed {
            fn complete_pass(&self, _: &Tid) -> bool {
                true
            }
        }
        match self.engine.reseal_due(&a, &Passed) {
            Ok(done) => self.take_done(done)?,
            Err(e) => self.diag(format!("re-seal of {a}: {e}")),
        }
        // the newest heartbeat of each node under the label, when it reports it stranded
        let me = self.engine.tid();
        let mut beats: BTreeMap<Tid, (osis_core::Ts, CommitId)> = BTreeMap::new();
        for ((_, _), e) in self.state.entries.range((l, BlobId([0; 32]))..).take_while(|((x, _), _)| *x == l) {
            let Kind::Commit { commit, .. } = &e.kind else { continue };
            let Some(h) = self.engine.header(commit) else { continue };
            if h.author == me || !h.aspects.iter().any(|x| x.ak.as_str() == "/seen" && x.tid == h.author) {
                continue;
            }
            if beats.get(&h.author).is_none_or(|(ts, _)| *ts < h.ts) {
                beats.insert(h.author, (h.ts, *commit));
            }
        }
        for (node, (_, c)) in beats {
            if self.resealed.contains(&c) || !self.engine.get_typed(&node, &ct::SEEN)?.is_some_and(|s| s.stranded) {
                continue;
            }
            self.resealed.insert(c);
            // the member of the actor the node reads through: itself or up its owner chain
            let members: BTreeSet<Tid> = self.engine.core.current_members(&a).into_iter().map(|x| x.0).collect();
            let mut cur = Some(node);
            for _ in 0..16 {
                let Some(t) = cur else { break };
                if members.contains(&t) {
                    // a node that may not re-seal that member leaves it to one that may
                    if let Ok(done) = self.engine.reshare(&a, &t) {
                        self.take_done(done)?;
                    }
                    break;
                }
                cur = match self.engine.core.created(&t) {
                    Some(osis_core::CreationRecord::Thing { owner, .. }) => Some(*owner),
                    _ => None,
                };
            }
        }
        Ok(())
    }

    /// This node's verdicts on label `l` at `server` under the keys its last pass there used
    /// (simulator invariants, spec/sync.md §6); `None` when the label is not open there.
    pub fn verdicts(&mut self, server: &ServerKey, l: &LabelId) -> Result<Option<Verdicts>> {
        let Some(lc) = self.conns.values().filter(|c| c.server == *server).find_map(|c| c.labels.get(l).filter(|x| x.phase == super::Phase::Open)) else { return Ok(None) };
        let (g, keys) = (lc.group, lc.keys.clone());
        let mut v = Verdicts { writer: keys.is_writer(), ..Verdicts::default() };
        let bodies = self.bodies_under(&g, l)?;
        let snaps = self.snapshots_at(l);
        let unsettled = self.unsettled(l, &g)?;
        v.unsettled = unsettled.iter().cloned().collect();
        let snapping = self.unsettled_hold(l, &g)?;
        for b in &bodies {
            if let Some(needed) = self.must_hold(b, &snaps, &snapping)? {
                v.must_hold.push((b.commit, needed));
            }
        }
        let entries: Vec<(BlobId, Entry)> = self.state.entries.range((*l, BlobId([0; 32]))..).take_while(|((x, _), _)| x == l).map(|((_, b), e)| (*b, e.clone())).collect();
        for (id, e) in entries {
            let j = self.judge(server, l, &g, &id, &e, &bodies, unsettled.is_empty())?;
            let Some((Hold::MustNot(why), live, aspects)) = j else { continue };
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

    /// The bodies label `l` of `g` should hold: the closure's; under a replaced label
    /// membership-class ones only (spec/sync.md §2: its content entries go).
    fn bodies_under(&mut self, g: &Tid, l: &LabelId) -> Result<Vec<Body>> {
        let mut bodies = self.engine.label_bodies(g)?;
        if self.is_replaced(g, l) {
            bodies.retain(|b| b.membership);
        }
        Ok(bodies)
    }

    fn is_replaced(&mut self, g: &Tid, l: &LabelId) -> bool {
        self.engine.group_labels(g).unwrap_or_default().iter().any(|x| x.id == *l && x.replaced)
    }

    /// Aspects where a body is not established uncovered yet (spec/sync.md §6), so not
    /// must-hold: those of pending snapshots (pages not fetched, deltas missing), and every
    /// aspect (`None`) while an entry of the label that opens under a held secret is being
    /// fetched (it may be a snapshot). Other pending commits settle nothing (two writers'
    /// pending commits otherwise withheld exactly what the other waited for), nor do entries
    /// that do not open as a commit or whose bytes no server delivers.
    fn unsettled_hold(&mut self, l: &LabelId, g: &Tid) -> Result<BTreeSet<Option<(Tid, Ak)>>> {
        let mut out = BTreeSet::new();
        let secrets = self.read_secrets(g);
        if self.state.entries.range((*l, BlobId([0; 32]))..).take_while(|((x, _), _)| x == l).any(|((_, b), e)| e.kind == Kind::Unknown && self.fetching.contains_key(b) && osis_label::unwrap_any(secrets.iter(), b, &e.wrap).is_some()) {
            out.insert(None);
        }
        for (c, r) in self.engine.pending() {
            if r == crate::Reason::Parked {
                continue;
            }
            let Some(bytes) = self.engine.commit_bytes(&c)? else { continue };
            if let Ok(cb) = osis_commit::CommitBlob::decode(&bytes)
                && is_snapshot(cb.header.kind)
            {
                out.extend(cb.header.aspects.iter().map(|a| Some((a.tid, a.ak.clone()))));
            }
        }
        Ok(out)
    }

    /// Entries present at `server` that unwrap under a held read secret and were never opened:
    /// opened now, or fetched again when their bytes are not here (a fetch lost to a cut or
    /// crash, secrets that arrived later).
    fn refetch(&mut self, conn: ConnId, server: ServerKey, l: LabelId, g: &Tid, out: &mut Vec<super::Action>) -> Result<()> {
        let secrets = self.read_secrets(g);
        let ids: Vec<BlobId> = self
            .state
            .entries
            .range((l, BlobId([0; 32]))..)
            .take_while(|((x, _), _)| *x == l)
            .filter(|((_, b), e)| e.kind == Kind::Unknown && !self.fetching.contains_key(b) && !self.missing.contains(&(conn, *b)) && self.state.is_present(&server, &l, b) && osis_label::unwrap_any(secrets.iter(), b, &e.wrap).is_some())
            .map(|((_, b), _)| *b)
            .collect();
        let (held, want): (Vec<BlobId>, Vec<BlobId>) = ids.into_iter().partition(|b| self.engine.has_blob(b));
        // bytes here but never opened under the secrets held now
        if !held.is_empty() {
            self.open_entries(l, &held)?;
        }
        if want.is_empty() {
            return Ok(());
        }
        for b in &want {
            self.fetching.insert(*b, conn);
        }
        self.command(conn, Command::Fetch { label: l, ids: want }, out)
    }

    /// Prefix vs header for commit blobs whose header lists went by link (spec/commits.md §4):
    /// checked once the applied header is resolved, before the entry counts as holding its
    /// body; a disagreeing blob is bad input (`Kind::Bad`) and the body is judged missing there.
    fn check_linked_prefixes(&mut self, l: LabelId) -> Result<()> {
        type Parts = Vec<(usize, usize)>;
        let todo: Vec<(BlobId, CommitId, Parts)> = self
            .state
            .entries
            .range((l, BlobId([0; 32]))..)
            .take_while(|((x, _), _)| *x == l)
            .filter(|((_, b), _)| !self.prefix_checked.contains(b))
            .filter_map(|((_, b), e)| match &e.kind {
                Kind::Commit { commit, parts } => Some((*b, *commit, parts.clone())),
                _ => None,
            })
            .filter(|(_, c, _)| self.engine.header(c).is_some_and(|h| osis_commit::ListField::ALL.iter().any(|f| h.links.get(*f).is_some())))
            .collect();
        for (b, c, parts) in todo {
            let Some(bytes) = self.engine.blob(&b)? else { continue };
            let Some(h) = self.engine.header(&c) else { continue };
            self.prefix_checked.insert(b);
            let agrees = match (osis_label::Prefix::parse(&bytes), osis_commit::prefix_inputs(&h, &parts)) {
                (Ok(p), Ok((expiry, tokens))) => {
                    let toks: Vec<(u8, [u8; 16])> = tokens.iter().map(|t| (t.level, t.hash)).collect();
                    parts.is_empty() || p.agrees(expiry.map(WallMs), &toks)
                }
                _ => false,
            };
            if !agrees {
                self.diag(format!("blob {b:?}: prefix disagrees with its resolved header"));
                if let Some(mut e) = self.state.entries.get(&(l, b)).cloned() {
                    e.kind = Kind::Bad;
                    self.state.set_entry(l, b, e);
                }
                self.state.remove_blob(&b);
            }
        }
        Ok(())
    }

    /// Aspects this node cannot judge deletions on yet: those of pending commits; every aspect
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
    fn promote(&mut self, conn: ConnId, server: ServerKey, l: LabelId, write: &osis_crypto::SigningSecret, uploads: &mut Vec<osis_proto::Entry>) -> Result<()> {
        let ids: Vec<(BlobId, Entry)> = self
            .state
            .entries
            .range((l, BlobId([0; 32]))..)
            .take_while(|((x, _), _)| *x == l)
            .filter(|((_, b), _)| self.state.deposited.contains(&(server, l, *b)))
            .map(|((_, b), e)| (*b, e.clone()))
            .collect();
        for (id, mut e) in ids {
            if super::in_flight(&self.sent, &(conn, l, id), self.raw_now()) {
                continue;
            }
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
            // still deposited there until the server takes the stamped upload (a refusal, say a
            // step registered meanwhile, leaves it for the next pass)
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

    /// Whether every part's aspect of commit `c` is covered by a snapshot under `l`.
    fn parts_covered(&mut self, l: &LabelId, c: &CommitId, h: &osis_commit::Header, parts: &[(usize, usize)]) -> Result<bool> {
        let snaps = self.snapshots_at(l);
        for (ai, _) in parts {
            let Some(a) = h.aspects.get(*ai) else { return Ok(false) };
            let mut ok = false;
            for s in snaps.get(&(a.tid, a.ak.clone())).into_iter().flatten() {
                if s != c && self.engine.covered(s, c, &a.tid, &a.ak)? == Some(true) {
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
        let closure = self.engine.closure(g);
        for (c, ais) in self.engine.certificates(g) {
            // the aspects this node's copies under the label carry: a chain grown since (an
            // owner's `/created` this node learned later) places the rest
            let placed: BTreeSet<usize> = self
                .state
                .entries
                .range((l, BlobId([0; 32]))..)
                .take_while(|((x, _), _)| *x == l)
                .filter_map(|(_, e)| match &e.kind {
                    Kind::Commit { commit, parts } if e.cert && *commit == c => Some(parts.iter().map(|(ai, _)| *ai).collect::<Vec<_>>()),
                    _ => None,
                })
                .flatten()
                .collect();
            // what the label's closure bodies carry is not copied again
            let inside: BTreeSet<usize> = self.engine.header(&c).map(|h| h.aspects.iter().enumerate().filter(|(_, a)| closure.contains(&a.tid)).map(|(i, _)| i).collect()).unwrap_or_default();
            let missing: BTreeSet<usize> = ais.difference(&placed).filter(|ai| placed.is_empty() || !inside.contains(ai)).copied().collect();
            // placed before and gone since (deleted at the server): not placed again
            if missing.is_empty() || placed.is_empty() && self.state.certs.contains(&(l, c)) {
                continue;
            }
            for b in self.engine.partial_bodies(&c, &missing)? {
                self.place(g, l, &b, true)?;
            }
            self.state.add_cert(l, c);
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
            && self.engine.get_typed(&me, &ct::SEEN).ok().flatten().is_some_and(|s| !s.stranded)
        {
            return Ok(Some(c));
        }
        // `ts` of the commit: the HLC's next wall time (spec/permissions.md §4)
        let ts = now.max(self.engine.core.hlc.last().wall_ms().0);
        let life = self.cfg.heartbeat_lifetime_ms.clamp(osis_core::format::HEARTBEAT_MIN_LIFETIME_MS, osis_core::format::HEARTBEAT_MAX_LIFETIME_MS);
        let mut m = crate::Mutation::new();
        // whole: a field left to an earlier heartbeat would go when that one expires (spec/crdt.md §9)
        m.replace(me, &ct::SEEN, &ct::Seen { ts: WallMs(ts), stranded })?;
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
        let ids: Vec<CommitId> = self.engine.core.commits.iter().filter(|(_, m)| m.header.kind.is_membership() && m.header.aspects.iter().any(|x| x.tid == a)).map(|(id, _)| *id).collect();
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
            let sups: Vec<Vec<(usize, usize)>> = self
                .state
                .entries
                .range((*l, BlobId([0; 32]))..)
                .take_while(|((x, _), _)| x == l)
                .filter(|((_, b), _)| b != id && self.state.present_anywhere(l, b))
                .filter_map(|(_, o)| match &o.kind {
                    Kind::Commit { commit: c2, parts: p2 } if c2 == commit && p2.len() > parts.len() && parts.iter().all(|p| p2.contains(p)) => Some(p2.clone()),
                    _ => None,
                })
                .collect();
            // a superset whose extra deltas a snapshot under the label covers carries nothing
            // more: this projection is one a right holder dropped them from (spec/sync.md §7)
            let mut sup = false;
            for p2 in sups {
                let extra: Vec<(usize, usize)> = p2.into_iter().filter(|p| !parts.contains(p)).collect();
                if !self.parts_covered(l, commit, &h, &extra)? {
                    sup = true;
                    break;
                }
            }
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
            if super::in_flight(&self.deleting, &(conn, l, id), self.raw_now()) {
                continue;
            }
            if let Some(item) = self.delete_for(keys, &l, &id, &e, None)? {
                let raw = self.raw_now();
                self.deleting.insert((conn, l, id), raw);
                items.push(item);
            }
        }
        // chunks of dropped deltas (spec/commits.md §5: a purge drops every body carrying the
        // values; spec/sync.md §3: chunk blobs belong to the closure)
        let chunks = self.dropped_chunks();
        for id in self.state.present_at(&server, &l) {
            let Some((c, ch)) = chunks.get(&id) else { continue };
            if !self.state.entries.get(&(l, id)).is_some_and(|e| e.kind == Kind::Unknown) || super::in_flight(&self.deleting, &(conn, l, id), self.raw_now()) {
                continue;
            }
            match self.chunk_delete(conn, keys, &l, &id, c, ch, out)? {
                Some(item) => {
                    let raw = self.raw_now();
                    self.deleting.insert((conn, l, id), raw);
                    items.push(item);
                }
                None => continue,
            }
        }
        // timed deletes: bodies under a relative keep-at-most with a known bound
        for b in bodies {
            let Some(id) = self.entry_for(&server, &l, b) else { continue };
            if !self.state.is_present(&server, &l, &id) || self.state.timed.contains(&(server, l, id)) || self.timed_sent.contains(&(conn, l, id)) {
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
                self.timed_sent.insert((conn, l, id));
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
            // the snapshot that covered the body when it was dropped, or one covered-equal to it
            // whose frontier holds the body's counters (a co-writer's that went up in its place);
            // a dropped body's content is gone, so `covered` checks only that frontier
            let carrier = self.carrier_of(commit, t, a);
            let candidates: Vec<CommitId> = match carrier {
                None if dropped => Vec::new(),
                _ => carrier.into_iter().chain(snaps.get(&(*t, a.clone())).cloned().unwrap_or_default()).collect(),
            };
            let mut ok = false;
            for s in candidates {
                if s == *commit || !self.state.entries.iter().any(|((x, b), o)| x == l && matches!(&o.kind, Kind::Commit { commit: c, .. } if *c == s) && self.state.is_present(server, l, b)) {
                    continue;
                }
                let covers = self.engine.covered(&s, commit, t, a)? == Some(true);
                let stand_in = match carrier {
                    Some(k) => k == s || (covers && self.engine.covered(&s, &k, t, a)? == Some(true) && self.engine.covered(&k, &s, t, a)? == Some(true)),
                    None => false,
                };
                if stand_in || (!dropped && covers) {
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
        if aspects.iter().all(|(t, a)| self.carrier_of(body, t, a).is_some()) {
            return Ok(());
        }
        for (t, a) in aspects {
            if is_membership(a) || self.engine.role_on(t) < Some(Role::Write) {
                continue;
            }
            if self.carrier_of(body, t, a).is_some() {
                continue;
            }
            // a snapshot from this node's whole state covers every body of the aspect it applied
            if let Some(s) = self.engine.snapshot(t, a)? {
                self.state.set_carrier(*body, s);
            }
        }
        Ok(())
    }

    /// The recorded carrier of a dropped body on `(t, a)`, followed through carriers that were
    /// dropped in turn to one whose body this node still holds (a carrier dropped before it went
    /// up carries nothing: its writes moved to a later snapshot, or a new one is due).
    fn carrier_of(&self, body: &CommitId, t: &Tid, a: &Ak) -> Option<CommitId> {
        let on = |c: &CommitId| self.engine.header(c).is_some_and(|h| h.aspects.iter().any(|x| x.tid == *t && x.ak == *a));
        let mut c = *self.state.carriers.get(body)?.iter().rev().find(|c| on(c))?;
        for _ in 0..64 {
            if self.engine.holds_body(&c, t, a) {
                return Some(c);
            }
            c = *self.state.carriers.get(&c)?.iter().rev().find(|c| on(c))?;
        }
        None
    }

    /// Chunk, tree-node and page blobs whose creating deltas this node dropped (purge, expiry,
    /// keep at most, compaction), by the commit and chunk entry that list them, unless a commit
    /// whose creating deltas are not all dropped lists them too (chunk reuse, spec/sync.md §1).
    /// A chunk's creating deltas are those whose token indices are its own (one class); with no
    /// such delta, every delta of the commit.
    pub(crate) fn dropped_chunks(&self) -> BTreeMap<BlobId, (CommitId, osis_commit::ChunkEntry)> {
        let mut out = BTreeMap::new();
        if !self.engine.core.commits.values().any(|m| !m.dropped.is_empty() && !m.header.chunks.is_empty()) {
            return out;
        }
        let mut live = BTreeSet::new();
        for (id, m) in &self.engine.core.commits {
            let h = &m.header;
            for ch in &h.chunks {
                let idx: Vec<usize> = ch.tokens.iter().map(|(i, _)| *i).collect();
                let class: Vec<usize> = h.aspects.iter().enumerate().filter(|(_, a)| a.tokens == idx).map(|(ai, _)| ai).collect();
                let ais: Vec<usize> = if class.is_empty() { (0..h.aspects.len()).collect() } else { class };
                let mut parts = ais.iter().flat_map(|ai| (0..h.aspects.get(*ai).map_or(0, |a| a.hashes.len())).map(move |di| (*ai, di))).peekable();
                let dropped = parts.peek().is_some() && parts.all(|p| m.dropped.contains(&p));
                if dropped {
                    out.entry(ch.blob).or_insert((*id, ch.clone()));
                } else {
                    live.insert(ch.blob);
                }
            }
        }
        out.retain(|b, _| !live.contains(b));
        out
    }

    /// A delete item for a dropped chunk: the delete key, else its chunk token (from the salt in
    /// its prefix; a chunk never fetched is fetched first).
    #[allow(clippy::too_many_arguments)]
    fn chunk_delete(&mut self, conn: ConnId, keys: &HeadKeys, l: &LabelId, id: &BlobId, c: &CommitId, ch: &osis_commit::ChunkEntry, out: &mut Vec<super::Action>) -> Result<Option<osis_label::DeleteItem>> {
        if keys.delete.is_some() {
            return Ok(delete_item(keys, l, *id, None, &[]));
        }
        let Some(blob) = self.engine.blob(id)? else {
            if !self.fetching.contains_key(id) && !self.missing.contains(&(conn, *id)) {
                self.fetching.insert(*id, conn);
                self.command(conn, Command::Fetch { label: *l, ids: vec![*id] }, out)?;
            }
            return Ok(None);
        };
        let Ok(prefix) = osis_label::Prefix::parse(&blob) else { return Ok(None) };
        let tokens = self.engine.chunk_tokens(c, ch, prefix.salt());
        Ok(delete_item(keys, l, *id, None, &tokens))
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
