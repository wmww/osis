//! The pass at one host for one label after its log was read to the end (spec/sync.md §5-§7;
//! spec/permissions.md §4): re-registration first when this admin holds newer epochs than the
//! head (the actor's role commits the host lacks, then the step; the rest after it is
//! registered), then uploads of must-hold bodies (role commits first) or relays of stamped ones,
//! this node's certificates and node card, heartbeats, and deletions of must-not-hold bodies
//! (`delete`: by the label delete key or a delete key, carriers first).

mod beats;
mod bodies;
mod certs;
mod delete;
mod inbox;
mod promote;
mod register;

use super::state::{BlobRec, Entry, Kind, HostKey, Touch};
use super::work::{Inputs, Left, Note, Scope, Work};
use super::{ConnId, SyncEngine};
use crate::error::Result;
use crate::labeling::{Body, BodyCtx, Facts, HeadKeys, Hold, Parts, Why, classify, delete_item, may_delete};
use osis_commit::Kind as CKind;
use osis_base::format::HEARTBEAT_MIN_INTERVAL_MS;
use osis_base::{Ak, BlobId, CommitId, LabelId, Role, Tid, WallMs};
use osis_proto::Command;
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};

/// A node's verdicts on one label at one host (`SyncEngine::verdicts`).
#[derive(Clone, Debug, Default)]
pub struct Verdicts {
    /// It stamps here (uploads what it judges must-hold).
    pub writer: bool,
    /// Bodies it judges must-hold: (commit, the delta parts no snapshot under the label covers).
    /// A live entry of the commit holding those parts and no dropped delta holds the body.
    pub must_hold: Vec<(CommitId, Vec<usize>)>,
    /// Entries it knows under the label that it judges must-not-hold and may delete now with a
    /// delete item it can make: (blob, why).
    pub must_not: Vec<(BlobId, String)>,
    /// Aspects it cannot judge coverage of yet (`None`: every aspect, an entry opens but is not
    /// applied).
    pub unsettled: Vec<Option<(Tid, Ak)>>,
}

/// How long another node's fresh demotion or `keys.0` is left to its author before this node
/// places it as its own chain certificate (ms; `settle_by` brings the pass back after).
const SETTLE_MS: u64 = 30_000;

/// The least a writer waits, after receiving another node's commit or seeing a deposit, before
/// it uploads or promotes it itself (ms); the most is `SETTLE_MS`. The point in between is this
/// node's per blob (`relay_delay`), so the author or the first co-writer is usually done and the
/// others skip it: writers online together otherwise each sent a copy (spec/sync.md §6, §7).
const RELAY_MIN_MS: u64 = 5_000;

/// An entry to send, by priority (role and certificates before content before
/// heartbeats).
struct Out {
    prio: u8,
    id: BlobId,
    /// Placed by this pass (a new encryption, or a linked blob's entry added).
    fresh: bool,
    /// What is judged again until the host has it (`Left`).
    of: Option<Touch>,
}

/// Chunks of dropped deltas with the commit and chunk entry listing them (`dropped_chunks`).
type DroppedChunks = BTreeMap<BlobId, (CommitId, osis_commit::ChunkEntry)>;

/// The bodies wanted under a label, by commit (`judge`).
type Desired = BTreeMap<CommitId, Vec<Vec<usize>>>;

fn desired(bodies: &[Body]) -> Desired {
    let mut m: Desired = BTreeMap::new();
    for b in bodies {
        m.entry(b.commit).or_default().push(b.parts.clone());
    }
    m
}

/// Whether an entry's live writes are carried, the aspects only a snapshot can carry, and the
/// capped rewrite it relies on (`SyncEngine::carried`).
type Carriage = (bool, Vec<(Tid, Ak)>, Option<BlobId>);

/// What may become of an entry judged under a label (`SyncEngine::deletable`).
#[allow(clippy::large_enum_variant)] // short-lived, one per judged entry
enum Fate {
    /// Not must-not-hold, or not judged.
    Keep,
    /// Must-not-hold, but its live writes wait for a carrier (a covering snapshot was asked
    /// for), or this node holds no delete item for it.
    Wait,
    /// Past its expiry: goes unattended.
    Expired,
    /// Goes, for this reason, by this delete item; with this node's rewrite the host refused
    /// for the label's cap that carries it (`carried`), only as a replacement in that rewrite's
    /// upload (spec/sync.md §5, §7).
    Delete(Why, osis_label::DeleteItem, Option<BlobId>),
}

/// Aspects not settled yet (`None`: every aspect; `SyncEngine::unsettled_sets`).
pub(crate) type Unsettled = BTreeSet<Option<(Tid, Ak)>>;

/// A judged entry: the rule's answer, whether it may carry live writes, its aspects.
type Judged = (Hold, bool, Vec<(Tid, Ak)>);

/// What a pass judges once its scope is taken (`SyncEngine::judging`).
struct J {
    scope: Scope,
    left: Left,
    snaps: Snaps,
    bodies: Vec<Body>,
    /// The commits of the scope when the bodies were taken (`judge_touched`).
    judged: BTreeSet<CommitId>,
    unsettled: Unsettled,
    snapping: Unsettled,
    replaced: bool,
}

/// A label's snapshots by aspect (`drop_label_covered`).
pub(crate) type Snaps = BTreeMap<(Tid, Ak), Vec<CommitId>>;

/// A pass's label of group `g` at `host` (`None`: the local pass) and head, with the keys
/// this node may use there (`usable_keys`).
struct Head {
    g: Tid,
    l: LabelId,
    host: Option<HostKey>,
    id: osis_label::StepId,
    keys: HeadKeys,
    read_ok: bool,
}

impl Head {
    fn at<'a>(&'a self, snaps: &'a Snaps, settled: bool) -> At<'a> {
        At { g: self.g, l: self.l, host: self.host, keys: &self.keys, snaps, settled }
    }
}

/// Where entries are judged (`judge`, `deletable` and below): label `l` of `g` at `host`
/// (`None`: this node's own served state, where every entry counts as present), under the
/// head's keys, with the label's snapshots and whether the view is settled.
struct At<'a> {
    g: Tid,
    l: LabelId,
    host: Option<HostKey>,
    keys: &'a HeadKeys,
    snaps: &'a Snaps,
    settled: bool,
}

/// A deposited entry due for promotion: (blob, entry, commit, its parts).
type Deposit = (BlobId, Entry, CommitId, Vec<usize>);

/// Whether a commit writes a heartbeat (`seen.0`).
fn is_beat(h: &osis_commit::Header) -> bool {
    h.aspects.iter().any(|a| a.ak.as_str() == "seen.0")
}

pub(super) fn is_snapshot(k: CKind) -> bool {
    matches!(k, CKind::ContentSnapshot | CKind::RoleSnapshot)
}

/// A node card's aspects (spec/permissions.md §4).
pub(super) fn is_card(ak: &str) -> bool {
    matches!(ak, "node.0" | "reach.0" | "keys.0")
}

/// What stays under a replaced label besides role-class commits (spec/sync.md §2).
pub(super) fn kept_when_replaced(ak: &str) -> bool {
    ct::is_role_class(ak) || matches!(ak, "created.0" | "node.0" | "reach.0" | "seen.0")
}

/// Every part of `h` on the aspects `keep` admits.
pub(crate) fn parts_of(h: &osis_commit::Header, keep: impl Fn(usize) -> bool) -> BTreeSet<usize> {
    (0..h.aspects.len()).filter(|i| keep(*i)).collect()
}

/// The aspect indexes of `h` on things of `closure` (what the label's closure bodies carry).
fn inside(h: &osis_commit::Header, closure: &BTreeSet<Tid>) -> BTreeSet<usize> {
    h.aspects.iter().enumerate().filter(|(_, a)| closure.contains(&a.tid)).map(|(i, _)| i).collect()
}

impl SyncEngine {
    pub(crate) fn pass(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<super::Action>) -> Result<()> {
        let _s = crate::costs::span("pass");
        let r = self.pass_at_host(conn, l, out);
        self.schedule_pass(Some(conn), l);
        r
    }

    /// When time alone next wants a pass of `l` (`Work::pass_at`): a due time of the work set, the
    /// roster's clock horizon, the next heartbeat. With none of those, one heartbeat interval from
    /// now: what no trigger names, should anything, waits no longer than a heartbeat does.
    fn schedule_pass(&mut self, conn: Option<ConnId>, l: LabelId) {
        let now = self.now();
        // not one past due: the pass just run had its chance (a label no more stranded, no budget)
        let beats: Vec<u64> = self.state.beats.get(&l).into_iter().chain(self.state.stranded.get(&l)).map(|t| t.saturating_add(HEARTBEAT_MIN_INTERVAL_MS)).filter(|t| *t > now).collect();
        let full_passes = self.cfg.full_passes;
        let Some(w) = self.work_mut(conn, l) else { return };
        let due = w.waits.due.keys().next().into_iter().chain(w.until.as_ref()).copied();
        let t = due.chain(beats).fold(now.saturating_add(HEARTBEAT_MIN_INTERVAL_MS), u64::min);
        w.pass_at = if full_passes { 0 } else { t };
    }

    /// `pass`, at a host.
    fn pass_at_host(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(c) = self.conns.get(&conn) else { return Ok(()) };
        let host = c.host;
        let Some(lc) = c.labels.get(&l) else { return Ok(()) };
        let (g, index) = (lc.group, lc.index);
        let Some(head) = lc.head.clone() else { return Ok(()) };
        // secrets may have arrived since the head was accepted
        self.recheck_doubts();
        let (keys, read_ok) = self.usable_keys(&g, index, &head)?;
        if let Some(lc) = self.lc_mut(conn, &l) {
            lc.keys = keys.clone();
        }
        if read_ok {
            self.place_deferred(&g)?;
        }
        // no secret of the head's read epoch: read first (spec/sync.md §5, reading without it),
        // stranded only once nothing more here opens
        if keys.epochs[0].is_none() {
            if self.read_first(conn, host, &g, l, out)? {
                return Ok(());
            }
            return self.stranded(conn, g, l, out);
        }
        if self.reregister(conn, l, out)? {
            return Ok(());
        }
        let p = Head { g, l, host: Some(host), id: head.id(), keys, read_ok };
        self.with_work(&g, Some(conn), l, |s, ctx, w| s.judge_label(conn, host, &p, ctx, w, out))
    }

    /// Certificate copies of `g` that waited for the rotation just run, or for a read secret.
    fn place_deferred(&mut self, g: &Tid) -> Result<()> {
        let (now, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.deferred).into_iter().partition(|x| x.0 == *g);
        self.deferred = later;
        let owed: BTreeSet<[u8; 32]> = now.iter().filter_map(|x| x.3).collect();
        for (x, c, ais, k) in now {
            self.place_certificate_in(&x, &c, &ais, k)?;
        }
        for k in owed {
            self.settle_owed(k);
        }
        Ok(())
    }

    /// Runs a pass of `l` of `g` over its work set (`conn` `None`: the local pass): the closure
    /// synced and the engine's changes spread first; what touches the set during the pass
    /// collects in its place and joins it after; a failed pass judges everything next time.
    fn with_work(&mut self, g: &Tid, conn: Option<ConnId>, l: LabelId, f: impl FnOnce(&mut Self, &BodyCtx, &mut Work) -> Result<()>) -> Result<()> {
        // this group's closure is synced (spec/sync.md §3)
        if !self.engine.core.ix.syncing.contains(g) {
            self.engine.set_syncing(*g, true)?;
        }
        // the group's closure, taken once for the pass
        let ctx = self.engine.body_ctx(g);
        // what an earlier pass of this step changed in the engine (a carrier snapshot written)
        self.engine_events()?;
        self.spread_touches();
        let Some(mut w) = self.work_mut(conn, l).map(std::mem::take) else { return Ok(()) };
        let r = f(self, &ctx, &mut w);
        if r.is_err() {
            w.touched.full = true;
        }
        if let Some(x) = self.work_mut(conn, l) {
            let meanwhile = std::mem::replace(x, w);
            x.merge(meanwhile);
        }
        r
    }

    /// The work set of `l` on `conn`, or of its local pass (`None`; made when missing).
    pub(super) fn work_mut(&mut self, conn: Option<ConnId>, l: LabelId) -> Option<&mut Work> {
        match conn {
            Some(c) => self.lc_mut(c, &l).map(|x| &mut x.work),
            None => Some(self.local_work.entry(l).or_insert_with(Work::fresh)),
        }
    }

    /// The pass after the keys and registration (`pass`): over what work set `w` names, or
    /// everything when it says so or an input of the pass changed (`work`).
    fn judge_label(&mut self, conn: ConnId, host: HostKey, p: &Head, ctx: &BodyCtx, w: &mut Work, out: &mut Vec<super::Action>) -> Result<()> {
        let (g, l, keys, read_ok) = (p.g, p.l, &p.keys, p.read_ok);
        let (full, scope) = self.begin(&g, &l, w, &ctx.closure);
        self.refetch(conn, host, l, w, out)?;
        // commits the refetch applied may move the closure or published groups: judged with
        // what holds now, as the inputs record it
        let fresh;
        let ctx = if self.engine.core.changed.as_ref().is_some_and(|c| !c.is_empty()) {
            fresh = self.engine.body_ctx(&g);
            &fresh
        } else {
            ctx
        };
        let J { mut scope, mut left, snaps, mut bodies, judged, unsettled, snapping, replaced } = self.judging(Some(conn), p, ctx, w, scope, full)?;
        // own memory writes wait while an own upload is in flight, then go coalesced
        // (spec/sync.md §9)
        self.coalesce_own(conn, l, ctx, &snaps, &mut bodies, &mut left)?;
        let mut sends: Vec<Out> = self.body_sends(p, &bodies, &snaps, &snapping, &mut left)?;
        // parked commits travel like at a host: stamped entries are relayed (spec/versioning.md §2)
        for id in self.state.of_kind(&l, Kind::TAG_PARKED) {
            if self.state.entries.get(&(l, id)).is_some_and(|e| e.stamp.is_some()) {
                sends.push(Out { prio: 3, id, fresh: false, of: None });
            }
        }
        if !replaced && (keys.is_writer() || keys.deposit.is_some()) && read_ok {
            let authors: BTreeSet<Tid> = w.unjudged.values().copied().collect();
            self.certificates(&g, l, &authors)?;
            let tight = self.lc(conn, &l).and_then(|x| x.budget).is_some_and(|b| b < self.cfg.tight_budget);
            self.heartbeat(&g, l, keys, tight, &ctx.closure)?;
        }
        if keys.write.is_some() && read_ok {
            self.complete_chains(conn, host, &g, l)?;
        }
        // every certificate copy this node placed here: chain, card, flows' placements,
        // promoted deposits' chains (those placed just now included)
        self.pull(Some(conn), &g, l, &mut scope, w);
        sends.extend(self.cert_sends(l, &scope));
        // a replaced label with everything to hold already there (`retire_at`)
        let quiet = replaced && sends.iter().all(|o| self.state.is_present(&host, &l, &o.id) || self.state.is_gone_at(&host, &l, &o.id));
        self.send(conn, host, p, sends, &mut left, out)?;
        self.clear_inbox(conn, host, p, out)?;
        // a commit deposited there this writer has not promoted yet: its chain may come
        if keys.write.is_some() {
            left.again |= self.state.deposited_at(&host, &l).into_iter().any(|b| self.promotable(&l, &b));
        }
        let settled = unsettled.is_empty();
        self.pull(Some(conn), &g, l, &mut scope, w);
        self.judge_touched(ctx, &g, &l, &scope, &judged, &mut bodies)?;
        self.deletions(conn, &p.at(&snaps, settled), &bodies, &scope, &mut left, out)?;
        if quiet && settled {
            self.retire_at(host, &g, l)?;
        }
        self.reseal(&g, l, w)?;
        // a snapshot from a state not whole yet repairs nothing
        if !self.filling(&l) {
            self.repair_suspects(w)?;
        }
        w.leave(left);
        Ok(())
    }

    /// Sends what a pass at `conn`'s host found to send, by priority: what the host lacks
    /// and is not in flight, stamped when this node writes (promoting due deposits too), else
    /// relayed with its stamp, else deposited (this node's own role writes queued in the
    /// outbox). What the host lacks is judged again next pass (`left`).
    fn send(&mut self, conn: ConnId, host: HostKey, p: &Head, mut sends: Vec<Out>, left: &mut Left, out: &mut Vec<super::Action>) -> Result<()> {
        let (g, l, keys) = (p.g, p.l, &p.keys);
        sends.sort_by_key(|o| o.prio);
        let raw = self.raw_now();
        let mut seen = BTreeSet::new();
        let mut uploads = Vec::new();
        let mut deposits = Vec::new();
        let mut queue = Vec::new();
        for o in sends {
            let settled = self.state.is_present(&host, &l, &o.id) || self.state.is_gone_at(&host, &l, &o.id);
            if !settled {
                // judged again next pass until the host has it
                match o.of {
                    Some(Touch::Commit(c)) => left.commits.insert(c),
                    Some(Touch::Blob(b)) => left.blobs.insert(b),
                    None => {
                        left.again = true;
                        false
                    }
                };
            }
            if !seen.insert(o.id) || settled || self.conns.get(&conn).is_some_and(|c| super::in_flight(c, &c.req.sent, (l, o.id), raw) || c.req.replacing.contains_key(&(l, o.id))) {
                continue;
            }
            let Some(e) = self.state.entries.get(&(l, o.id)).cloned() else { continue };
            let Some(blob) = self.engine.blob(&o.id)? else { continue };
            if let Some(w) = &keys.write {
                uploads.push(self.stamped_upload(l, o.id, e, blob, w));
            } else if let Some(stamp) = e.stamp {
                uploads.push(osis_proto::Entry { blob, wrap: e.wrap, stamp, replaces: Vec::new() });
            } else if let Some(d) = &keys.deposit
                && self.mine(&e)
                // a queued deposit goes from the outbox
                && !self.state.outbox.contains_key(&(host, l, o.id))
            {
                if e.cert || !matches!(e.kind, Kind::Commit { .. }) {
                    let sig = osis_label::sign_deposit(d, &l, &o.id, &e.wrap);
                    deposits.push((blob, e.wrap, sig));
                } else {
                    // this node's own role write: queued, so neither a crash nor
                    // forgetting the label recalls it
                    queue.push((blob, e.wrap, d.clone()));
                }
            }
        }
        if !queue.is_empty() {
            let hosts: Vec<osis_label::Address> = self.engine.labels_of(&g).into_iter().find(|x| x.id == l).map(|x| x.hosts.clone()).unwrap_or_default();
            for (blob, wrap, d) in queue {
                let id = osis_label::blob_id(&blob);
                let at: Vec<osis_label::Address> = hosts.iter().filter(|a| !self.state.is_present(&a.key, &l, &id)).cloned().collect();
                self.queue_deposit(l, &at, &d, blob, wrap, None);
            }
            self.send_outbox(out)?;
        }
        if let Some(w) = &keys.write {
            self.promote(conn, host, &g, l, w, &mut uploads)?;
            self.stamp_inbox(conn, host, l, w, &mut uploads)?;
        }
        let ids: Vec<BlobId> = uploads.iter().map(|u| osis_label::blob_id(&u.blob)).collect();
        for b in &ids {
            self.note_own_upload(conn, l, *b);
        }
        if let Some(c) = self.conns.get_mut(&conn) {
            c.req.sent.extend(ids.into_iter().chain(deposits.iter().map(|d| osis_label::blob_id(&d.0))).map(|b| ((l, b), (raw, super::UNTAGGED))));
        }
        if !uploads.is_empty() {
            self.command(conn, Command::Upload { label: l, entries: uploads }, out)?;
        }
        for (blob, wrap, sig) in deposits {
            self.command(conn, Command::Deposit { label: l, blob, wrap, sig }, out)?;
        }
        self.given(conn);
        Ok(())
    }

    /// Stamps entry `id` under `l` and keeps the stamp, so a later pass does not promote it again.
    pub(super) fn stamp_entry(&mut self, l: LabelId, id: BlobId, mut e: Entry, write: &osis_crypto::SigningSecret) -> osis_crypto::Signature {
        let stamp = osis_label::sign_stamp(write, &l, &id, &e.wrap);
        e.stamp = Some(stamp);
        self.state.set_entry(l, id, e);
        stamp
    }

    /// `stamp_entry`, as an upload of `blob`.
    pub(super) fn stamped_upload(&mut self, l: LabelId, id: BlobId, e: Entry, blob: Vec<u8>, write: &osis_crypto::SigningSecret) -> osis_proto::Entry {
        let wrap = e.wrap;
        let stamp = self.stamp_entry(l, id, e, write);
        osis_proto::Entry { blob, wrap, stamp, replaces: Vec::new() }
    }

    /// Readies `w` for a pass (`prepare`): whether it judges everything, and its scope.
    fn begin(&mut self, g: &Tid, l: &LabelId, w: &mut Work, closure: &std::sync::Arc<BTreeSet<Tid>>) -> (bool, Scope) {
        let full = self.prepare(g, l, w, closure);
        self.stats.passes += 1;
        let scope = if full { Scope::All } else { Scope::Some { commits: std::mem::take(&mut w.touched.commits), blobs: std::mem::take(&mut w.touched.blobs) } };
        (full, scope)
    }

    /// What a pass judges (`judge_label`, `judge_local`; `conn` `None`: the local pass): the
    /// scope with what touched the set meanwhile, the unsettled sets and the inputs taken
    /// (`take_inputs`), the label's snapshots with the bodies they cover dropped, and the bodies
    /// of the scope. A host's entries get their linked prefixes checked.
    fn judging(&mut self, conn: Option<ConnId>, p: &Head, ctx: &BodyCtx, w: &mut Work, mut scope: Scope, full: bool) -> Result<J> {
        let (g, l, keys) = (&p.g, p.l, &p.keys);
        self.pull(conn, g, l, &mut scope, w);
        if conn.is_some() {
            self.check_linked_prefixes(l, &scope)?;
        }
        let fetching = w.unopened.iter().any(|b| self.fetching(b));
        let sets = self.unsettled_sets(!w.unopened.is_empty(), fetching)?;
        let replaced = self.is_replaced(g, &l);
        let inputs = Inputs {
            head: Some(p.id),
            epochs: keys.epochs,
            roles: Inputs::roles(keys, p.read_ok),
            replaced,
            actor: self.engine.group_actor(g),
            published: ctx.published.clone(),
            may_rotate: self.may_rotate_read(g),
            held: self.engine.epochs(g),
        };
        if self.take_inputs(p, w, &mut scope, full, inputs, &sets) && !full && conn.is_some() {
            self.check_linked_prefixes(l, &scope)?;
        }
        let (unsettled, snapping) = sets;
        let mut left = Left::default();
        let entries = w.snaps.clone();
        let snaps = self.drop_label_covered(&entries, &mut scope, &mut left)?;
        let bodies = self.bodies_in(ctx, g, &l, &scope)?;
        let judged: BTreeSet<CommitId> = match &scope {
            Scope::Some { commits, .. } => commits.clone(),
            Scope::All => BTreeSet::new(),
        };
        Ok(J { scope, left, snaps, bodies, judged, unsettled, snapping, replaced })
    }

    /// Entries touched during the pass are judged against their commits' bodies too: the bodies
    /// of the commits `scope` gained since `judged`.
    fn judge_touched(&mut self, ctx: &BodyCtx, g: &Tid, l: &LabelId, scope: &Scope, judged: &BTreeSet<CommitId>, bodies: &mut Vec<Body>) -> Result<()> {
        if let Scope::Some { commits, .. } = scope {
            let more = Scope::Some { commits: commits.difference(judged).copied().collect(), blobs: BTreeSet::new() };
            bodies.extend(self.bodies_in(ctx, g, l, &more)?);
        }
        Ok(())
    }

    /// The pass inputs and unsettled sets of `w` (`judge_label`, `judge_local`): a changed
    /// input judges everything (`full`); what was judged while unsettled is judged again once
    /// settled (becoming unsettled only withholds actions, and what is outside the set has none
    /// outstanding), and so are the commits of aspects that became or stopped being unsettled.
    /// Returns whether the pass judges everything.
    fn take_inputs(&mut self, p: &Head, w: &mut Work, scope: &mut Scope, mut full: bool, inputs: Inputs, (unsettled, snapping): &(Unsettled, Unsettled)) -> bool {
        let withheld = (!unsettled.is_empty(), snapping.contains(&None));
        let release = w.withheld.0 && !withheld.0 || w.withheld.1 && !withheld.1;
        w.withheld = withheld;
        let mut moved: BTreeSet<(Tid, Ak)> = unsettled.iter().chain(snapping.iter()).flatten().cloned().collect();
        let was: BTreeSet<(Tid, Ak)> = w.unsettled.iter().flatten().cloned().collect();
        moved = moved.symmetric_difference(&was).cloned().collect();
        w.unsettled = unsettled.iter().chain(snapping.iter()).cloned().collect();
        if w.inputs.as_ref() != Some(&inputs) && !full {
            full = true;
            *scope = Scope::All;
            let closure = w.closure.clone();
            self.go_full(&p.g, &p.l, w, &closure);
        }
        w.inputs = Some(inputs);
        if let Scope::Some { commits, .. } = scope {
            if release {
                commits.extend(std::mem::take(&mut w.waits.held_back));
            }
            for (t, a) in &moved {
                commits.extend(self.engine.core.held_on(&(*t, a.clone())));
            }
        }
        if full {
            self.stats.full += 1;
            drop(crate::costs::span("pass: full"));
        }
        full
    }

    /// Local passes over every label this node syncs, against its own store: what the label
    /// must hold of this node's is placed there whatever hosts are connected, so a reader
    /// pulling its stream (a direct link's redeemer, spec/permissions.md §7, or a co-reader
    /// either side dialed) finds its own writes (spec/sync.md §5, Placed and co-reader peer);
    /// a host pass uploads what its host lacks of it. A label with no host in its `label.0`
    /// has this node as its host: its local pass also issues steps, promotes, deletes and
    /// re-seals, as a host pass does at a host.
    pub(crate) fn local_passes(&mut self) -> Result<()> {
        self.local_dirty = false;
        self.local_last = self.raw_now();
        // a node no reader can pull (it neither dials co-readers nor is dialable) serves nothing
        if !self.serves_readers() {
            self.local_any = false;
            return Ok(());
        }
        let labels: Vec<(Tid, LabelId, u64, bool)> = self.labels().into_iter().filter(|(_, l)| !l.replaced).map(|(g, l)| (g, l.id, l.index, super::peers::hostless(&l.hosts))).collect();
        self.local_any = !labels.is_empty();
        if labels.is_empty() {
            return Ok(());
        }
        let served = self.served_labels();
        self.local_work.retain(|x, _| labels.iter().any(|(_, l, _, _)| l == x));
        for (g, l, index, host) in labels {
            let Some(head) = served.get(&l).and_then(|s| s.head()) else { continue };
            // one label's failure stops neither the others nor the handle
            if let Err(e) = self.local_pass(g, l, index, head, host) {
                self.diag(format!("local pass of {l:?}: {e}"));
            }
            self.schedule_pass(None, l);
        }
        Ok(())
    }

    /// The keys of `head` this node may use, and whether read is covered: never encrypt under an
    /// epoch that does not cover a known departure, so rotate first (flows' cascade), else hold
    /// back what the uncovered roles would sign or wrap.
    fn usable_keys(&mut self, g: &Tid, index: u64, head: &osis_label::Step) -> Result<(HeadKeys, bool)> {
        let mut keys = self.engine.head_keys(g, index, head)?;
        let still = self.uncovered(g, true)?;
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
        Ok((keys, read_ok))
    }

    /// One label's local pass: what a pass would upload is placed in this node's store
    /// (`body_sends`: the must-hold bodies and the blobs they link; inbox copies,
    /// certificates), stamped when this node writes. With `host` (no host in `label.0`) it
    /// leaves this node's store as a pass at a host would leave that host: a newer established
    /// epoch first issues a child step of the head when that head is recorded in `label.0`
    /// (recorded there, so the served head moves; `reregister` without the upload), and the pass
    /// goes on under it; the heartbeat is placed, deposits promoted, then `local_deletions` and
    /// re-seals.
    fn local_pass(&mut self, g: Tid, l: LabelId, index: u64, head: &osis_label::Step, host: bool) -> Result<()> {
        let _s = crate::costs::span("pass: local");
        let (mut keys, read_ok) = self.usable_keys(&g, index, head)?;
        let recorded = self.group_label(&g, &l).is_some_and(|gl| gl.steps.contains_key(&head.id()));
        if host && recorded && self.step_due(&g, &l, &keys) && self.step_settled(&g, l) {
            let (step, done) = self.engine.issue_step(&g, &l, &head.id(), false)?;
            self.take_done(done)?;
            if let Some((step, _)) = step {
                self.served_cache = None;
                keys = self.usable_keys(&g, index, &step)?.0;
            }
        }
        if read_ok {
            self.place_deferred(&g)?;
        }
        if !read_ok || keys.epochs[0].is_none() || !(keys.is_writer() || keys.deposit.is_some()) {
            return Ok(());
        }
        // the label's work set, as at a host (`judge_label`)
        let p = Head { g, l, host: None, id: head.id(), keys, read_ok };
        self.with_work(&g, None, l, |s, ctx, w| s.judge_local(&p, host, ctx, w))
    }

    /// The local pass after the keys and the step (`local_pass`; `host`: this node is the
    /// label's host), over what work set `w` names, or everything when it says so or an input
    /// of the pass changed.
    fn judge_local(&mut self, p: &Head, host: bool, ctx: &BodyCtx, w: &mut Work) -> Result<()> {
        let (g, l, keys) = (p.g, p.l, &p.keys);
        let (full, scope) = self.begin(&g, &l, w, &ctx.closure);
        let J { mut scope, mut left, snaps, mut bodies, judged, snapping, .. } = self.judging(None, p, ctx, w, scope, full)?;
        let sends = self.body_sends(p, &bodies, &snaps, &snapping, &mut left)?;
        let ours: BTreeSet<BlobId> = sends.iter().filter(|o| o.fresh).map(|o| o.id).collect();
        let authors: BTreeSet<Tid> = w.unjudged.values().copied().collect();
        self.certificates(&g, l, &authors)?;
        if host {
            self.heartbeat(&g, l, keys, false, &ctx.closure)?;
            if let Some(wk) = &keys.write {
                self.local_promote(&g, l, wk, &scope, &ours, &mut left)?;
            }
        }
        // what the placements just made touched (certificate copies, the heartbeat)
        self.pull(None, &g, l, &mut scope, w);
        if let Some(wk) = &keys.write {
            // stamped as an upload would be (another node's deposits: `local_promote`)
            let mut cands = self.scope_entries(&l, &scope);
            if !scope.is_all() {
                cands.extend(&ours);
            }
            for id in cands {
                let Some(e) = self.state.entries.get(&(l, id)).cloned() else { continue };
                if e.stamp.is_none() && (e.cert || ours.contains(&id)) {
                    self.stamp_entry(l, id, e, wk);
                }
            }
        }
        if host {
            let settled = self.unsettled_sets(!w.unopened.is_empty(), false)?.0.is_empty();
            self.judge_touched(ctx, &g, &l, &scope, &judged, &mut bodies)?;
            self.local_deletions(&p.at(&snaps, settled), &bodies, &scope, &mut left)?;
            // a node serving the label alone decides here: nobody runs a pass at a host for it
            self.reseal(&g, l, w)?;
            self.repair_suspects(w)?;
        }
        w.leave(left);
        Ok(())
    }

    /// The entries under `l` in `scope`: every one, or those of its commits and its blobs.
    fn scope_entries(&self, l: &LabelId, scope: &Scope) -> BTreeSet<BlobId> {
        match scope {
            Scope::All => self.state.label_entries(l).map(|(b, _)| b).collect(),
            Scope::Some { commits, blobs } => commits.iter().flat_map(|c| self.state.entries_of(l, c).map(|(b, _)| b)).chain(blobs.iter().copied()).collect(),
        }
    }

    /// Unopened entries under `l` in `scope` that `keep` admits, as chunk candidates
    /// (`dropped_chunks`): every one, or those its commits list and its blobs.
    fn chunk_entries(&self, l: &LabelId, scope: &Scope, keep: impl Fn(&Self, &BlobId) -> bool) -> BTreeSet<BlobId> {
        match scope {
            Scope::All => self.state.of_kind(l, Kind::TAG_UNKNOWN).into_iter().filter(|b| keep(self, b)).collect(),
            Scope::Some { commits, blobs } => {
                let listed = commits.iter().filter_map(|c| self.engine.header(c)).flat_map(|h| h.chunks.iter().map(|ch| ch.blob).collect::<Vec<_>>());
                listed.chain(blobs.iter().copied()).filter(|b| self.state.entries.get(&(*l, *b)).is_some_and(|e| e.kind == Kind::Unknown) && keep(self, b)).collect()
            }
        }
    }

    /// The commits this node placed certificate copies of under `l` whose linked blobs `scope`
    /// judges: those of its commits, every one when a linked entry is in it.
    fn copies_in(&self, l: &LabelId, scope: &Scope) -> Vec<CommitId> {
        let every = match scope {
            Scope::Some { blobs, .. } => blobs.iter().any(|b| self.state.cert_entries.contains(&(*l, *b))),
            Scope::All => true,
        };
        self.state.certs.range((*l, CommitId([0; 32]))..=(*l, CommitId([0xff; 32]))).map(|(_, c)| *c).filter(|c| every || scope.has(c)).collect()
    }

    /// The entries under `l` that certificate copies of `copied` placed for the blobs they link
    /// (`place_linked`), of the commits no entry under `l` holds any more (spec/sync.md §3).
    fn copy_links(&mut self, l: &LabelId, copied: Vec<CommitId>) -> Result<BTreeSet<BlobId>> {
        let mut out = BTreeSet::new();
        for c in copied {
            if self.state.entries_of(l, &c).next().is_some() {
                continue;
            }
            let Some(h) = self.engine.header(&c) else { continue };
            let all = parts_of(&h, |_| true);
            for b in self.engine.linked_blobs(&c, &all)? {
                if self.state.entries.get(&(*l, b)).is_some_and(|e| e.cert && e.kind == Kind::Unknown) {
                    out.insert(b);
                }
            }
        }
        Ok(out)
    }

    /// The blobs the commit entries among `ids` under `l` link (other copies sharing tree blobs
    /// with a gone copy).
    fn linked_by(&mut self, l: &LabelId, ids: impl IntoIterator<Item = BlobId>) -> Result<BTreeSet<BlobId>> {
        let commits: Vec<(CommitId, BTreeSet<usize>)> = ids
            .into_iter()
            .filter_map(|id| match self.state.entries.get(&(*l, id)).map(|e| &e.kind) {
                Some(Kind::Commit { commit, parts, .. }) => Some((*commit, parts.iter().copied().collect())),
                _ => None,
            })
            .collect();
        let mut out = BTreeSet::new();
        for (c, parts) in commits {
            out.extend(self.engine.linked_blobs(&c, &parts)?);
        }
        Ok(out)
    }

    /// Drops the bytes of a blob whose entry under a label synced with nobody went: a commit
    /// blob's record and bytes once no entry names it, any other blob's bytes likewise.
    fn forget_entry_blob(&mut self, id: &BlobId) -> Result<()> {
        if self.state.named(id) {
            return Ok(());
        }
        if self.state.blobs.contains_key(id) {
            self.state.remove_blob(id);
        }
        self.delete_blobs(&[*id])
    }

    /// The content snapshots under `l` (`entries`: by aspect, from their entries), this node's
    /// own included (a carrier it wrote for a body it must delete covers others too): drops the
    /// bodies they cover (spec/sync.md §7), so every right holder holding the same snapshots
    /// drops alike; a snapshot judges every body of its aspect when in `scope`, else the bodies
    /// `scope` names. Dropped bodies join `scope`. Returns the label's snapshots by aspect.
    pub(super) fn drop_label_covered(&mut self, entries: &BTreeMap<(Tid, Ak), BTreeSet<(BlobId, CommitId)>>, scope: &mut Scope, left: &mut Left) -> Result<Snaps> {
        let snaps: BTreeMap<(Tid, Ak), Vec<CommitId>> = entries.iter().map(|(k, v)| (k.clone(), v.iter().map(|(_, c)| *c).collect())).collect();
        let mut dropped: BTreeSet<CommitId> = BTreeSet::new();
        for ((t, a), ss) in &snaps {
            // a memory snapshot's covered drops are Core's, at apply (spec/sync.md §9: an own
            // body drops only under an own snapshot)
            if a.ephemeral() {
                continue;
            }
            // by commit, not by blob: which cover a body drops under (its carrier) is not the luck
            // of the random stream its blobs were sealed with
            let ss: BTreeSet<CommitId> = ss.iter().copied().collect();
            for s in &ss {
                let snapshot = self.engine.core.ix.commits.get(s).is_some_and(|m| m.header.kind == CKind::ContentSnapshot);
                if !snapshot && !self.engine.own_replace(s, t, a) {
                    continue;
                }
                // an own replace (spec/commits.md §5): the author's older commits the scope names
                // (the work set adds what arriving replaces newly let go); every one in a full pass
                if !snapshot {
                    let only: Vec<CommitId> = match &*scope {
                        Scope::Some { commits, .. } => commits.iter().filter(|c| self.engine.own_older(s, c, t, a)).copied().collect(),
                        _ => self.engine.own_held_before(s, t, a),
                    };
                    if !only.is_empty() {
                        dropped.extend(self.drop_covered(t, a, s, Some(&only), left)?);
                    }
                    continue;
                }
                let only: Option<Vec<CommitId>> = match &*scope {
                    Scope::Some { commits, .. } if !commits.contains(s) => Some(commits.iter().filter(|c| self.engine.header(c).is_some_and(|h| h.aspects.iter().any(|x| x.tid == *t && x.ak == *a))).copied().collect()),
                    _ => None,
                };
                if only.as_ref().is_some_and(|o| o.is_empty()) {
                    continue;
                }
                dropped.extend(self.drop_covered(t, a, s, only.as_deref(), left)?);
            }
        }
        let all = self.cfg.full_passes;
        self.forget_dropped(if all { None } else { Some(&dropped) })?;
        if let Scope::Some { commits, .. } = scope {
            commits.extend(dropped);
        }
        Ok(snaps)
    }

    /// Entries present at `host` that unwrap under a held read secret and were never opened:
    /// opened now, or fetched again when their bytes are not here (a fetch lost to a cut or
    /// crash, secrets that arrived later).
    fn refetch(&mut self, conn: ConnId, host: HostKey, l: LabelId, w: &Work, out: &mut Vec<super::Action>) -> Result<()> {
        // a fill asks for them in order
        if self.lc(conn, &l).is_some_and(|x| x.fill.is_some()) {
            return Ok(());
        }
        let ids: Vec<BlobId> = w.unopened.iter().copied().collect();
        self.open_or_fetch(conn, host, l, ids, out).map(|_| ())
    }

    /// `refetch` of every entry of `l` for a node holding no secret of the head's read epoch
    /// (its pass stops there, so the work set's `unopened` is not kept). Invariant: such a node
    /// is stranded only when no entry present at `host` unwraps under a read secret it holds
    /// and is unopened. An entry listed before the secret its wrap opens under arrived was not
    /// fetched then: the head's rotation commit is one when it is wrapped under an epoch this
    /// node learned later, another rotation's or a fork's (spec/crypto.md §5; member_churn
    /// seeds 9, 9390: an admin that never read it never registered or uploaded again). True
    /// while something is fetched or opened.
    fn read_first(&mut self, conn: ConnId, host: HostKey, g: &Tid, l: LabelId, out: &mut Vec<super::Action>) -> Result<bool> {
        let secrets = self.read_secrets(g);
        let ids: Vec<BlobId> = self.state.of_kind(&l, Kind::TAG_UNKNOWN).into_iter().filter(|b| self.state.entries.get(&(l, *b)).is_some_and(|e| e.unopened(b, &secrets))).collect();
        let busy = ids.iter().any(|b| self.fetching(b));
        Ok(self.open_or_fetch(conn, host, l, ids, out)? || busy)
    }

    /// Of unopened entries `ids` of `l`: those whose bytes are here are opened under the
    /// secrets held now, the rest present at `host` fetched (a fetch lost to a cut or crash,
    /// secrets that arrived later). Whether any was fetched or opened.
    fn open_or_fetch(&mut self, conn: ConnId, host: HostKey, l: LabelId, ids: Vec<BlobId>, out: &mut Vec<super::Action>) -> Result<bool> {
        let missing = |s: &Self, b: &BlobId| s.conns.get(&conn).is_some_and(|c| c.req.missing.contains(b));
        let ids: Vec<BlobId> = ids.into_iter().filter(|b| !self.fetching(b) && !missing(self, b) && self.state.is_present(&host, &l, b) && !self.memory_skips(&l, b)).collect();
        let (held, want): (Vec<BlobId>, Vec<BlobId>) = ids.into_iter().partition(|b| self.engine.has_blob(b));
        if !held.is_empty() {
            self.open_entries(Some(conn), l, &held)?;
        }
        let opened = held.iter().any(|b| self.state.entries.get(&(l, *b)).is_some_and(|e| e.kind != Kind::Unknown));
        let fetched = !want.is_empty();
        self.fetch_on(conn, l, want, out)?;
        Ok(opened || fetched)
    }

    /// Aspects this node cannot judge deletions on yet: those of pending commits; every aspect
    /// (`None` in the set) while an entry of the label opens under a held secret and is not
    /// applied (`unopened`: a snapshot not fetched or applied yet, spec/sync.md §6: may-hold).
    /// And the aspects where a body is not established uncovered yet (spec/sync.md §6), so not
    /// must-hold: those of pending snapshots (pages not fetched, deltas missing), and every aspect
    /// (`None`) while an entry of the label that opens under a held secret is being fetched
    /// (`fetching`; it may be a snapshot). Other pending commits settle nothing there, nor do
    /// entries that do not open as a commit or whose bytes no host delivers.
    pub(super) fn unsettled_sets(&mut self, unopened: bool, fetching: bool) -> Result<(Unsettled, Unsettled)> {
        // what pends moves only with the engine
        let at = (self.engine.core.generation, self.engine.core.memory_generation);
        let (mut all, mut snaps) = match self.unsettled_memo.clone().filter(|(k, ..)| *k == at) {
            Some((_, all, snaps)) => {
                #[cfg(debug_assertions)]
                assert!(self.pending_sets()? == (all.clone(), snaps.clone()), "unsettled_sets cached");
                (all, snaps)
            }
            None => {
                let (all, snaps) = self.pending_sets()?;
                self.unsettled_memo = Some((at, all.clone(), snaps.clone()));
                (all, snaps)
            }
        };
        if unopened {
            all.insert(None);
        }
        if fetching {
            snaps.insert(None);
        }
        Ok((all, snaps))
    }

    /// The aspects of pending commits, and of pending snapshots.
    fn pending_sets(&mut self) -> Result<(Unsettled, Unsettled)> {
        let (mut all, mut snaps) = (BTreeSet::new(), BTreeSet::new());
        for (c, r) in self.engine.pending() {
            if r == crate::Reason::Parked {
                continue;
            }
            let Some(bytes) = self.engine.commit_bytes(&c)? else { continue };
            let Ok(cb) = osis_commit::CommitBlob::decode_stored(&bytes) else { continue };
            let aspects = cb.header.aspects.iter().map(|a| Some((a.tid, a.ak.clone())));
            if is_snapshot(cb.header.kind) {
                snaps.extend(aspects.clone());
            }
            all.extend(aspects);
        }
        Ok((all, snaps))
    }
}
