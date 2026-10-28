//! The pass at one server for one label after its log was read to the end (spec/sync.md §5-§7;
//! spec/permissions.md §4): re-registration first when this admin holds newer epochs than the
//! head (the actor's membership commits the server lacks, then the step; the rest after it is
//! registered), then uploads of must-hold bodies (membership first) or relays of stamped ones,
//! this node's certificates and node card, heartbeats, and deletions of must-not-hold bodies
//! (by the label delete key or a delete key, carriers first), timed deletes for relative keep-at-most.

use super::state::{BlobRec, Entry, Kind, ServerKey, Touch};
use super::work::{Inputs, Left, Note, Scope, Work};
use super::{ConnId, SyncEngine};
use crate::error::Result;
use crate::labeling::{Body, BodyCtx, Facts, HeadKeys, Hold, Parts, Why, classify, delete_item, may_delete, seal_body};
use osis_commit::Kind as CKind;
use osis_base::format::HEARTBEAT_MIN_INTERVAL_MS;
use osis_base::{Ak, BlobId, CommitId, LabelId, Role, Tid, WallMs};
use osis_proto::Command;
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};

/// A node's verdicts on one label at one server (`SyncEngine::verdicts`).
#[derive(Clone, Debug, Default)]
pub struct Verdicts {
    /// It stamps here (uploads what it judges must-hold).
    pub writer: bool,
    /// Bodies it judges must-hold: (commit, the delta parts no snapshot under the label covers).
    /// A live entry of the commit holding those parts and no dropped delta holds the body.
    pub must_hold: Vec<(CommitId, Vec<(usize, usize)>)>,
    /// Entries it knows under the label that it judges must-not-hold and may delete now with a
    /// delete item it can make: (blob, why).
    pub must_not: Vec<(BlobId, String)>,
    /// Aspects it cannot judge coverage of yet (`None`: every aspect, an entry opens but is not
    /// applied).
    pub unsettled: Vec<Option<(Tid, Ak)>>,
}

/// How long another node's fresh demotion or `/keys` is left to its author before this node
/// places it as its own chain certificate (ms; the periodic pass picks it up after).
const SETTLE_MS: u64 = 30_000;

/// The least a writer waits, after receiving another node's commit or seeing a deposit, before
/// it uploads or promotes it itself (ms); the most is `SETTLE_MS`. The point in between is this
/// node's per blob (`relay_due`), so the author or the first co-writer is usually done and the
/// others skip it: writers online together otherwise each sent a copy (spec/sync.md §6, §7).
const RELAY_MIN_MS: u64 = 5_000;

/// An entry to send, by priority (membership and certificates before content before
/// heartbeats).
struct Out {
    prio: u8,
    id: BlobId,
    /// Placed by this pass (a new encryption, or a linked blob's entry added).
    fresh: bool,
    /// What is judged again until the server has it (`Left`).
    of: Option<Touch>,
}

/// Chunks of dropped deltas with the commit and chunk entry listing them (`dropped_chunks`).
type DroppedChunks = BTreeMap<BlobId, (CommitId, osis_commit::ChunkEntry)>;

/// The bodies wanted under a label, by commit (`judge`).
type Desired = BTreeMap<CommitId, Vec<Vec<(usize, usize)>>>;

fn desired(bodies: &[Body]) -> Desired {
    let mut m: Desired = BTreeMap::new();
    for b in bodies {
        m.entry(b.commit).or_default().push(b.parts.clone());
    }
    m
}

/// What may become of an entry judged under a label (`SyncEngine::deletable`).
enum Fate {
    /// Not must-not-hold, or not judged.
    Keep,
    /// Must-not-hold, but its live writes wait for a carrier (a covering snapshot was asked
    /// for), or this node holds no delete item for it.
    Wait,
    /// Past its expiry: goes unattended.
    Expired,
    /// Goes, for this reason, by this delete item.
    Delete(Why, osis_label::DeleteItem),
}

/// What a keep-at-most body before its timed delete waits on (`keep_at_most_due`), its aspect.
enum AtMost {
    /// No write died: only a death (it marks the body) or another change of the aspect's state
    /// (`Work::at_most`) changes its bound or liveness.
    Live(Tid, Ak),
    /// A write died: any write may also drop the dots it still holds (`Work::waits`).
    Dead(Tid, Ak),
}

/// A timed delete due: the entry and its time (`keep_at_most_due`).
type TimedDue = Option<(Entry, u64)>;

/// Aspects not settled yet (`None`: every aspect; `SyncEngine::unsettled_sets`).
type Unsettled = BTreeSet<Option<(Tid, Ak)>>;

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
type Snaps = BTreeMap<(Tid, Ak), Vec<CommitId>>;

/// A pass's label of group `g` at `server` (`None`: the local pass) and head, with the keys
/// this node may use there (`usable_keys`).
struct Head {
    g: Tid,
    l: LabelId,
    server: Option<ServerKey>,
    id: osis_label::StepId,
    keys: HeadKeys,
    read_ok: bool,
}

impl Head {
    fn at<'a>(&'a self, snaps: &'a Snaps, settled: bool) -> At<'a> {
        At { g: self.g, l: self.l, server: self.server, keys: &self.keys, snaps, settled }
    }
}

/// Where entries are judged (`judge`, `deletable` and below): label `l` of `g` at `server`
/// (`None`: this node's own served state, where every entry counts as present), under the
/// head's keys, with the label's snapshots and whether the view is settled.
struct At<'a> {
    g: Tid,
    l: LabelId,
    server: Option<ServerKey>,
    keys: &'a HeadKeys,
    snaps: &'a Snaps,
    settled: bool,
}

/// A deposited entry due for promotion: (blob, entry, commit, its parts).
type Deposit = (BlobId, Entry, CommitId, Vec<(usize, usize)>);

pub(super) fn is_snapshot(k: CKind) -> bool {
    matches!(k, CKind::ContentSnapshot | CKind::MembershipSnapshot)
}

/// A node card's aspects (spec/permissions.md §4).
pub(super) fn is_card(ak: &str) -> bool {
    matches!(ak, "/node" | "/reach" | "/keys")
}

/// What stays under a replaced label besides membership-class commits (spec/sync.md §2).
pub(super) fn kept_when_replaced(ak: &str) -> bool {
    ct::is_membership_class(ak) || matches!(ak, "/created" | "/node" | "/reach" | "/seen")
}

/// Every part of `h` on the aspects `keep` admits.
pub(super) fn parts_of(h: &osis_commit::Header, keep: impl Fn(usize) -> bool) -> BTreeSet<(usize, usize)> {
    h.aspects.iter().enumerate().filter(|(i, _)| keep(*i)).flat_map(|(i, a)| (0..a.hashes.len()).map(move |d| (i, d))).collect()
}

/// The aspect indexes of `h` on things of `closure` (what the label's closure bodies carry).
fn inside(h: &osis_commit::Header, closure: &BTreeSet<Tid>) -> BTreeSet<usize> {
    h.aspects.iter().enumerate().filter(|(_, a)| closure.contains(&a.tid)).map(|(i, _)| i).collect()
}

impl SyncEngine {
    pub(crate) fn pass(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(c) = self.conns.get(&conn) else { return Ok(()) };
        let server = c.server;
        let Some(lc) = c.labels.get(&l) else { return Ok(()) };
        let (g, index) = (lc.group, lc.index.unwrap_or(0));
        let Some(head) = lc.head.clone() else { return Ok(()) };
        // secrets may have arrived since the head was accepted
        let (keys, read_ok) = self.usable_keys(&g, index, &head)?;
        if let Some(lc) = self.lc_mut(conn, &l) {
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
        let p = Head { g, l, server: Some(server), id: head.id(), keys, read_ok };
        self.with_work(&g, Some(conn), l, |s, ctx, w| s.judge_label(conn, &p, ctx, w, out))
    }

    /// Runs a pass of `l` of `g` over its work set (`conn` `None`: the local pass): the closure
    /// synced and the engine's changes spread first; what touches the set during the pass
    /// collects in its place and joins it after; a failed pass judges everything next time.
    fn with_work(&mut self, g: &Tid, conn: Option<ConnId>, l: LabelId, f: impl FnOnce(&mut Self, &BodyCtx, &mut Work) -> Result<()>) -> Result<()> {
        // the group's closure, taken once for the pass; atomic apply waits for its deltas
        // (spec/commits.md §4)
        let ctx = self.engine.body_ctx(g);
        self.sync_closure(g, &ctx.closure)?;
        // what an earlier pass of this step changed in the engine (a carrier snapshot written)
        self.engine_events()?;
        self.spread_touches();
        let Some(mut w) = self.work_mut(conn, l).map(std::mem::take) else { return Ok(()) };
        let r = f(self, &ctx, &mut w);
        if r.is_err() {
            w.full = true;
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

    /// Atomic apply waits for the deltas of every thing of `g`'s closure (spec/commits.md §4):
    /// walked only when the closure changed since the last time (`Groups::closures`).
    fn sync_closure(&mut self, g: &Tid, closure: &std::sync::Arc<BTreeSet<Tid>>) -> Result<()> {
        if self.synced_closures.get(g).is_some_and(|c| super::work::same_closure(c, closure)) {
            return Ok(());
        }
        self.stats.closures += 1;
        for t in closure.iter() {
            if !self.engine.core.ix.syncing.contains(t) {
                self.engine.set_syncing(*t, true)?;
            }
        }
        self.synced_closures.insert(*g, closure.clone());
        Ok(())
    }

    /// The pass after the keys and registration (`pass`): over what work set `w` names, or
    /// everything when it says so or an input of the pass changed (`work`).
    fn judge_label(&mut self, conn: ConnId, p: &Head, ctx: &BodyCtx, w: &mut Work, out: &mut Vec<super::Action>) -> Result<()> {
        let (g, l, keys, read_ok) = (p.g, p.l, &p.keys, p.read_ok);
        let Some(server) = p.server else { return Ok(()) };
        let (full, scope) = self.begin(&g, &l, w, &ctx.closure);
        self.refetch(conn, server, l, w, out)?;
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
        let mut sends: Vec<Out> = self.body_sends(p, &bodies, &snaps, &snapping, &mut left)?;
        // parked commits travel like at a blind node: stamped entries are relayed (spec/versioning.md §2)
        for id in self.state.of_kind(&l, 4) {
            if self.state.entries.get(&(l, id)).is_some_and(|e| e.stamp.is_some()) {
                sends.push(Out { prio: 3, id, fresh: false, of: None });
            }
        }
        let mut held = BTreeSet::new();
        if !replaced && (keys.is_writer() || keys.deposit.is_some()) {
            if read_ok {
                self.inbox_copies(&g, l)?;
                let authors: BTreeSet<Tid> = w.unjudged.values().copied().collect();
                held = self.certificates(&g, l, false, &authors)?;
                let tight = self.lc(conn, &l).and_then(|x| x.budget).is_some_and(|b| b < self.cfg.tight_budget);
                self.heartbeat(&g, l, keys, tight)?;
            } else if !self.may_rotate_read(&g) {
                // the revokes of departures inside members only: they tell the label's rotators
                // what keeps its epoch uncovered (spec/permissions.md §4 exception)
                held = self.certificates(&g, l, true, &BTreeSet::new())?;
            }
        }
        if keys.write.is_some() && read_ok {
            self.complete_chains(conn, server, &g, l)?;
        }
        // every certificate copy this node placed here: chain, card, flows' placements,
        // promoted deposits' chains (those placed just now included)
        self.pull(Some(conn), &g, l, &mut scope, w);
        sends.extend(self.cert_sends(l, &scope));
        // a replaced label with everything to hold already there (`retire_at`)
        let quiet = replaced && sends.iter().all(|o| self.state.is_present(&server, &l, &o.id) || self.state.gone.contains(&(server, l, o.id)));
        self.send(conn, p, sends, &held, &mut left, out)?;
        let settled = unsettled.is_empty();
        self.pull(Some(conn), &g, l, &mut scope, w);
        self.judge_touched(ctx, &g, &l, &scope, &judged, &mut bodies)?;
        self.deletions(conn, &p.at(&snaps, settled), &bodies, &scope, &mut left, out)?;
        if quiet && settled {
            self.retire_at(server, &g, l)?;
        }
        self.reseal(&g, w)?;
        w.leave(left);
        Ok(())
    }

    /// Every certificate copy this node placed under `l` in `scope` to send: chain, card, flows'
    /// placements, promoted deposits' chains.
    fn cert_sends(&self, l: LabelId, scope: &Scope) -> Vec<Out> {
        let mut sends = Vec::new();
        for id in self.cert_entries(&l, scope) {
            let Some(e) = self.state.entries.get(&(l, id)) else { continue };
            let c = if let Kind::Commit { commit, .. } = &e.kind { Some(*commit) } else { None };
            let beat = c.and_then(|c| self.engine.header(&c)).is_some_and(|h| h.aspects.iter().any(|a| a.ak.as_str() == "/seen"));
            let prio = if c.is_some_and(|c| self.first.contains(&c)) {
                0
            } else if beat {
                4
            } else {
                2
            };
            sends.push(Out { prio, id, fresh: false, of: Some(c.map_or(Touch::Blob(id), Touch::Commit)) });
        }
        sends
    }

    /// Sends what a pass at `conn`'s server found to send, by priority: what the server lacks
    /// and is not in flight, stamped when this node writes (promoting due deposits too), else
    /// relayed with its stamp, else deposited (this node's own membership writes queued in the
    /// outbox). This node's write waits while a certificate copy of its chain is `held`. What the
    /// server lacks is judged again next pass (`left`).
    fn send(&mut self, conn: ConnId, p: &Head, mut sends: Vec<Out>, held: &BTreeSet<CommitId>, left: &mut Left, out: &mut Vec<super::Action>) -> Result<()> {
        let (g, l, keys) = (p.g, p.l, &p.keys);
        let Some(server) = p.server else { return Ok(()) };
        sends.sort_by_key(|o| o.prio);
        let raw = self.raw_now();
        let mut seen = BTreeSet::new();
        let mut uploads = Vec::new();
        let mut deposits = Vec::new();
        let mut queue = Vec::new();
        for o in sends {
            let settled = self.state.is_present(&server, &l, &o.id) || self.state.gone.contains(&(server, l, o.id));
            if !settled {
                // judged again next pass until the server has it
                match o.of {
                    Some(Touch::Commit(c)) => left.commits.insert(c),
                    Some(Touch::Blob(b)) => left.blobs.insert(b),
                    None => false,
                };
            }
            if !seen.insert(o.id) || settled || self.conns.get(&conn).is_some_and(|c| super::in_flight(&c.req.sent, (l, o.id), raw)) {
                continue;
            }
            let Some(e) = self.state.entries.get(&(l, o.id)).cloned() else { continue };
            // this node's write here waits while a certificate copy of its chain is held
            // (`hold`): it never goes before its chain (removals excepted, spec/sync.md §5)
            if !held.is_empty()
                && !e.cert
                && let Kind::Commit { commit, parts, .. } = &e.kind
                && self.own(commit)
                && self.engine.header(commit).is_some_and(|h| h.frontier.is_none())
                && self.engine.author_chain(commit, &parts.iter().copied().collect()).is_some_and(|ch| ch.keys().any(|x| held.contains(x)))
            {
                continue;
            }
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
                // a queued deposit goes from the outbox
                && !self.state.outbox.contains_key(&(server, l, o.id))
            {
                if e.cert || !matches!(e.kind, Kind::Commit { .. }) {
                    let sig = osis_label::sign_deposit(d, &l, &o.id, &e.wrap);
                    deposits.push((blob, e.wrap, sig));
                } else {
                    // this node's own membership write: queued, so neither a crash nor
                    // forgetting the label recalls it
                    queue.push((blob, e.wrap, d.clone()));
                }
            }
        }
        if !queue.is_empty() {
            let servers: Vec<osis_label::Address> = self.engine.labels_of(&g).into_iter().find(|x| x.id == l).map(|x| x.servers.clone()).unwrap_or_default();
            for (blob, wrap, d) in queue {
                let id = osis_label::blob_id(&blob);
                let at: Vec<osis_label::Address> = servers.iter().filter(|a| !self.state.is_present(&a.key, &l, &id)).cloned().collect();
                self.queue_deposit(l, &at, &d, blob, wrap);
            }
            self.send_outbox(out)?;
        }
        if let Some(w) = &keys.write {
            self.promote(conn, server, &g, l, w, &mut uploads)?;
        }
        if let Some(c) = self.conns.get_mut(&conn) {
            c.req.sent.extend(uploads.iter().map(|u| osis_label::blob_id(&u.blob)).chain(deposits.iter().map(|d| osis_label::blob_id(&d.0))).map(|b| ((l, b), raw)));
        }
        if !uploads.is_empty() {
            self.command(conn, Command::Upload { label: l, entries: uploads }, out)?;
        }
        for (blob, wrap, sig) in deposits {
            self.command(conn, Command::Deposit { label: l, blob, wrap, sig }, out)?;
        }
        Ok(())
    }

    /// Readies `w` for a pass (`prepare`): whether it judges everything, and its scope.
    fn begin(&mut self, g: &Tid, l: &LabelId, w: &mut Work, closure: &std::sync::Arc<BTreeSet<Tid>>) -> (bool, Scope) {
        let full = self.prepare(g, l, w, closure);
        self.stats.passes += 1;
        let scope = if full { Scope::All } else { Scope::Some { commits: std::mem::take(&mut w.commits), blobs: std::mem::take(&mut w.blobs) } };
        (full, scope)
    }

    /// What a pass judges (`judge_label`, `judge_local`; `conn` `None`: the local pass): the
    /// scope with what touched the set meanwhile, the unsettled sets and the inputs taken
    /// (`take_inputs`), the label's snapshots with the bodies they cover dropped, and the bodies
    /// of the scope. A server's entries get their linked prefixes checked.
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
        let flags = (unsettled.is_empty(), !snapping.contains(&None));
        let release = w.settled.is_some_and(|(s, n)| !s && flags.0 || !n && flags.1);
        w.settled = Some(flags);
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
                commits.extend(std::mem::take(&mut w.held_back));
            }
            for (t, a) in &moved {
                commits.extend(self.engine.core.ix.by_aspect.get(&(*t, a.clone())).into_iter().flatten().map(|x| x.1));
            }
        }
        if full {
            self.stats.full += 1;
        }
        full
    }

    /// Local passes over the labels this node syncs with nobody (no server in their `/label`):
    /// this node is their server, so a peer that dials it (a direct link's redeemer,
    /// spec/permissions.md §9) finds a complete state (spec/sync.md §5, member peer). Passes
    /// otherwise run only per dialed connection, and a node serves only the entries they placed.
    pub(crate) fn local_passes(&mut self) -> Result<()> {
        self.local_dirty = false;
        self.local_last = self.raw_now();
        // nobody can dial a node without `/reach` (no listener): nothing to serve
        if self.own_reach().is_none() {
            self.local_any = false;
            return Ok(());
        }
        let labels: Vec<(Tid, LabelId, u64)> = self.labels().into_iter().filter(|(_, l)| !l.replaced && l.servers.iter().all(super::peers::is_peer)).map(|(g, l)| (g, l.id, l.index)).collect();
        self.local_any = !labels.is_empty();
        if labels.is_empty() {
            return Ok(());
        }
        let served = self.served_labels();
        self.local_work.retain(|x, _| labels.iter().any(|(_, l, _)| l == x));
        for (g, l, index) in labels {
            let Some(head) = served.get(&l).and_then(|s| s.head()) else { continue };
            // one label's failure stops neither the others nor the handle
            if let Err(e) = self.local_pass(g, l, index, head) {
                self.diag(format!("local pass of {l:?}: {e}"));
            }
        }
        Ok(())
    }

    /// The keys of `head` this node may use, and whether read is covered: never encrypt under an
    /// epoch that does not cover a known departure, so rotate first (flows' cascade), else hold
    /// back what the uncovered roles would sign or wrap.
    fn usable_keys(&mut self, g: &Tid, index: u64, head: &osis_label::Step) -> Result<(HeadKeys, bool)> {
        let mut keys = self.engine.head_keys(g, index, head)?;
        let still = self.uncovered(g)?;
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

    /// Whether this node may issue a new step for a label of `g` now: another node's rotation
    /// of the actor (a `/secrets` write) received less than `SETTLE_MS` ago is its author's to
    /// register first (a second admin's step, issued before the author's reaches it, would be a
    /// sibling); a wake brings the pass back then. Other membership writes (an admin recording
    /// a step in `/label`, a `/keys` update) get no step from their author and delay nothing.
    fn step_settled(&mut self, g: &Tid) -> bool {
        let a = self.engine.core.secret_actor(g).unwrap_or(*g);
        let Some(t) = self.rotation_at.get(&a).map(|t| t.saturating_add(SETTLE_MS)) else { return true };
        if t <= self.raw_now() {
            return true;
        }
        self.settle_by(t);
        false
    }

    /// One label's local pass, as a pass at a server would leave that server: a newer
    /// established epoch first issues a child step of the head when that head is recorded in
    /// `/label` (recorded there, so the served head moves; `reregister` without the upload),
    /// and the pass goes on under it; then what a pass would upload is placed (`body_sends`:
    /// the must-hold bodies and the blobs they link; inbox copies, certificates, the
    /// heartbeat), stamped when this node writes; carriers are asked for before keep-at-most
    /// bounds; then `local_deletions`.
    fn local_pass(&mut self, g: Tid, l: LabelId, index: u64, head: &osis_label::Step) -> Result<()> {
        let (mut keys, read_ok) = self.usable_keys(&g, index, head)?;
        let recorded = self.group_label(&g, &l).is_some_and(|gl| gl.steps.contains_key(&head.id()));
        if recorded && self.step_due(&g, &l, &keys) && self.step_settled(&g) {
            let (step, done) = self.engine.issue_step(&g, &l, &head.id(), false)?;
            self.take_done(done)?;
            if let Some((step, _)) = step {
                self.served_cache = None;
                keys = self.usable_keys(&g, index, &step)?.0;
            }
        }
        if !read_ok || keys.epochs[0].is_none() || !(keys.is_writer() || keys.deposit.is_some()) {
            return Ok(());
        }
        // the label's work set, as at a server (`judge_label`)
        let p = Head { g, l, server: None, id: head.id(), keys, read_ok };
        self.with_work(&g, None, l, |s, ctx, w| s.judge_local(&p, ctx, w))
    }

    /// The local pass after the keys and the step (`local_pass`), over what work set `w`
    /// names, or everything when it says so or an input of the pass changed.
    fn judge_local(&mut self, p: &Head, ctx: &BodyCtx, w: &mut Work) -> Result<()> {
        let (g, l, keys) = (p.g, p.l, &p.keys);
        let (full, scope) = self.begin(&g, &l, w, &ctx.closure);
        let J { mut scope, mut left, snaps, mut bodies, judged, snapping, .. } = self.judging(None, p, ctx, w, scope, full)?;
        let sends = self.body_sends(p, &bodies, &snaps, &snapping, &mut left)?;
        let ours: BTreeSet<BlobId> = sends.iter().filter(|o| o.fresh).map(|o| o.id).collect();
        self.inbox_copies(&g, l)?;
        let authors: BTreeSet<Tid> = w.unjudged.values().copied().collect();
        self.certificates(&g, l, false, &authors)?;
        self.heartbeat(&g, l, keys, false)?;
        // what the placements just made touched (certificate copies, the heartbeat)
        self.pull(None, &g, l, &mut scope, w);
        if let Some(wk) = &keys.write {
            // stamped as an upload would be; another node's deposits stay deposits
            let mut cands = self.scope_entries(&l, &scope);
            if !scope.is_all() {
                cands.extend(&ours);
            }
            for id in cands {
                let Some(mut e) = self.state.entries.get(&(l, id)).cloned() else { continue };
                if e.stamp.is_none() && (e.cert || ours.contains(&id)) {
                    e.stamp = Some(osis_label::sign_stamp(wk, &l, &id, &e.wrap));
                    self.state.set_entry(l, id, e);
                }
            }
        }
        let settled = self.unsettled_of(!w.unopened.is_empty())?.is_empty();
        self.judge_touched(ctx, &g, &l, &scope, &judged, &mut bodies)?;
        self.local_deletions(&p.at(&snaps, settled), &bodies, &scope, &mut left)?;
        w.leave(left);
        Ok(())
    }

    /// The deletion step of a local pass, over the entries of `scope` no server or peer holds
    /// (those go by their deletions, spec/sync.md §5-§7): a commit entry goes as `deletable` says
    /// (a live body only with a carrier, a covering snapshot asked for meanwhile, even when its
    /// bytes are gone), an expired one outright; any other entry whose bytes this node no longer
    /// holds serves nothing and goes, one past its prefix's expiry goes outright (a heartbeat's
    /// chunk, an inbox blob); chunks of dropped deltas go, and the blobs a gone certificate copy
    /// linked. Removed entries are tombstoned (`State::remove_entry`), expired ones not. What
    /// waits goes into `left`.
    fn local_deletions(&mut self, at: &At, bodies: &[Body], scope: &Scope, left: &mut Left) -> Result<()> {
        let (l, settled) = (at.l, at.settled);
        let ids: Vec<BlobId> = self.scope_entries(&l, scope).into_iter().filter(|id| self.state.entries.contains_key(&(l, *id)) && !self.state.present_anywhere(&l, id)).collect();
        self.stats.entries += ids.len() as u64;
        let now = self.now();
        let desired = desired(bodies);
        let mut note = Note::default();
        for id in ids {
            let Some(e) = self.state.entries.get(&(l, id)).cloned() else { continue };
            let held = self.engine.has_blob(&id);
            if let Kind::Commit { commit, .. } = e.kind {
                let fate = self.deletable(at, &id, &e, &desired, true, &mut note)?;
                note.leave(commit, left);
                if !settled {
                    left.held_back.insert(commit);
                }
                match fate {
                    Fate::Wait => continue,
                    Fate::Expired => {
                        self.state.drop_entry(l, id);
                        self.forget_entry_blob(&id)?;
                        continue;
                    }
                    Fate::Delete(..) => {
                        self.state.remove_entry(l, id);
                        self.forget_entry_blob(&id)?;
                        continue;
                    }
                    Fate::Keep if held => continue,
                    Fate::Keep => {}
                }
            }
            if !held {
                self.state.drop_entry(l, id);
                self.local_expiry.remove(&id);
                continue;
            }
            let expiry = match self.local_expiry.get(&id) {
                Some(x) => *x,
                None => {
                    let x = self.engine.blob(&id)?.and_then(|b| osis_label::Prefix::parse(&b).ok()).and_then(|p| p.expiry()).map(|t| t.0);
                    self.local_expiry.insert(id, x);
                    x
                }
            };
            match expiry {
                Some(t) if t <= now => {
                    self.state.drop_entry(l, id);
                    self.local_expiry.remove(&id);
                    self.forget_entry_blob(&id)?;
                }
                Some(t) => {
                    left.due_blobs.entry(t).or_default().insert(id);
                }
                None => {}
            }
        }
        // chunks of dropped deltas (a purge, spec/commits.md §5): those listed by the commits of
        // `scope` and the chunk entries it names
        let cands = self.chunk_entries(&l, scope, |s, b| !s.state.present_anywhere(&l, b));
        let (chunks, waiting) = self.dropped_chunks(&cands)?;
        left.blobs.extend(waiting);
        for b in chunks.into_keys() {
            self.state.remove_entry(l, b);
            self.local_expiry.remove(&b);
            self.forget_chunk(&b)?;
        }
        // the blobs certificate copies linked, as a pass at a server deletes them (the bytes
        // stay: they are the engine's own): of the copies in `scope`, of every one when a
        // linked entry is
        let copied = self.copies_in(&l, scope);
        let mut gone = self.copy_links(&l, copied)?;
        gone.retain(|b| !self.state.present_anywhere(&l, b));
        if !gone.is_empty() {
            let all: Vec<BlobId> = self.state.label_entries(&l).map(|(b, _)| b).collect();
            for b in self.linked_by(&l, all)? {
                gone.remove(&b);
            }
        }
        for b in gone {
            self.state.remove_entry(l, b);
            self.local_expiry.remove(&b);
        }
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
            Scope::All => self.state.of_kind(l, 0).into_iter().filter(|b| keep(self, b)).collect(),
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

    /// The blobs the commit entries among `ids` under `l` link (roster snapshots sharing tree
    /// pages with a gone copy).
    fn linked_by(&mut self, l: &LabelId, ids: impl IntoIterator<Item = BlobId>) -> Result<BTreeSet<BlobId>> {
        let commits: Vec<(CommitId, BTreeSet<(usize, usize)>)> = ids
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
        let mut dropped = BTreeSet::new();
        for ((t, a), ss) in &snaps {
            for s in ss {
                if !self.engine.core.ix.commits.get(s).is_some_and(|m| m.header.kind == CKind::ContentSnapshot) {
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

    /// The entries the must-hold bodies of `l` need (spec/sync.md §6), by priority: the entry of
    /// each body (at `server` if there, else any genuine one; `None`: this node's own served
    /// state, any entry), else a fresh placement when this node may upload or deposit it, with
    /// the blobs it links when this node writes. Another node's body not at `server` waits for
    /// its author or a co-writer (`relay_due`).
    fn body_sends(&mut self, p: &Head, bodies: &[Body], snaps: &Snaps, snapping: &Unsettled, left: &mut Left) -> Result<Vec<Out>> {
        let (g, l, keys, read_ok, server) = (&p.g, p.l, &p.keys, p.read_ok, p.server.as_ref());
        let mut sends = Vec::new();
        self.stats.bodies += bodies.len() as u64;
        let mut note = Note::default();
        for b in bodies {
            let needed = self.must_hold(b, snaps, snapping, &mut note)?;
            note.leave(b.commit, left);
            if snapping.contains(&None) {
                left.held_back.insert(b.commit);
            }
            let Some(needed) = needed else { continue };
            let entry = self.entry_for(server, &l, b);
            // another blob of the commit holding every needed delta holds it (a projection a
            // right holder dropped covered deltas from, a superset), unless it is must-not-hold
            // (`holds_nothing`, spec/sync.md §6)
            let here = entry.is_some_and(|id| server.is_none_or(|s| self.state.is_present(s, &l, &id)));
            if !here && self.carried_by(server, g, &l, &b.commit, &needed) {
                continue;
            }
            // another node's commit not at this server: its author (or a co-writer) first
            if !here && !self.relay_due(&b.commit) {
                left.commits.insert(b.commit);
                continue;
            }
            let (id, fresh) = match entry {
                Some(id) => (id, false),
                None if read_ok && (keys.is_writer() || self.may_deposit(keys, b)) => match self.place(g, l, b, false)? {
                    Some(id) => (id, true),
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
            let of = Some(Touch::Commit(b.commit));
            sends.push(Out { prio, id, fresh, of });
            if keys.is_writer() {
                let mut linked = self.chunk_blobs(&b.commit)?;
                // chunks the header lists that are not here yet go up once they arrive
                if let Some(h) = self.engine.header(&b.commit) {
                    for ch in &h.chunks {
                        if !linked.contains(&ch.blob) {
                            left.links.entry(ch.blob).or_default().insert(b.commit);
                        }
                    }
                }
                linked.extend(self.body_blobs(&l, b, left)?);
                for cb in linked {
                    let fresh = !self.state.entries.contains_key(&(l, cb));
                    if fresh {
                        let wrap = osis_crypto::filler_wrap(&mut *self.rng);
                        self.state.set_entry(l, cb, Entry { wrap, stamp: None, cert: false, kind: Kind::Unknown });
                    }
                    sends.push(Out { prio, id: cb, fresh, of });
                }
            }
        }
        Ok(sends)
    }

    /// Whether this admin re-registers `l` of `g` before anything else (spec/sync.md §5): it
    /// holds, established, the head's epochs (`keys`) and a newer one; a replaced label never.
    fn step_due(&mut self, g: &Tid, l: &LabelId, keys: &HeadKeys) -> bool {
        keys.delete.is_some() && keys.write.is_some() && !self.is_replaced(g, l) && self.engine.epochs(g).is_some_and(|e| osis_keys::newer_than_head(&e, keys.epochs))
    }

    /// What may become of entry `id` under `l` (spec/sync.md §6, §7): `judge`, then a live
    /// body goes only with a carrier (`carried`; else a covering snapshot is asked for,
    /// `snapshot_first`, when `carrier`) and by a delete item this node can make. `server`
    /// `None`: this node's own served state.
    fn deletable(&mut self, at: &At, id: &BlobId, e: &Entry, desired: &Desired, carrier: bool, note: &mut Note) -> Result<Fate> {
        let Some((Hold::MustNot(why), live, aspects)) = self.judge(at, id, e, desired, note)? else { return Ok(Fate::Keep) };
        if why == Why::Expired {
            return Ok(Fate::Expired);
        }
        let (carried, need) = match why {
            _ if !live => (true, Vec::new()),
            Why::Duplicate | Why::StrictSubset => (true, Vec::new()),
            _ => self.carried(at, e)?,
        };
        if !may_delete(why, live, carried) {
            if carrier && let Kind::Commit { commit, .. } = &e.kind {
                self.snapshot_first(&need, commit)?;
            }
            // judged again once a write on its aspects changes liveness (a carrier is a trigger)
            note.waits.extend(aspects);
            return Ok(Fate::Wait);
        }
        Ok(match self.delete_for(at.keys, &at.l, id, e, None)? {
            Some(item) => Fate::Delete(why, item),
            None => {
                note.keyless = true;
                Fate::Wait
            }
        })
    }

    /// A body under a relative keep-at-most with a known bound and no live write, held by entry
    /// `id` under `l` (spec/commits.md §5): its entry and bound, for a timed delete. A body with
    /// a live write gets none: it goes at the next compaction or its bound, carried then
    /// (`deletable`), so an edit erasing part of it does not re-snapshot the aspect. `None`: not
    /// under a relative keep-at-most; else what the body waits on and, when due, entry and bound.
    fn keep_at_most_due(&mut self, l: &LabelId, b: &Body, id: &BlobId) -> Result<Option<(AtMost, TimedDue)>> {
        let Some(h) = self.engine.header(&b.commit) else { return Ok(None) };
        let Some(a) = b.parts.first().and_then(|(ai, _)| h.aspects.get(*ai)) else { return Ok(None) };
        if a.retention.at_most.rel.is_none() {
            return Ok(None);
        }
        let (tid, ak) = (a.tid, a.ak.clone());
        // deaths and bound first: liveness costs a look through the state (cached per aspect)
        let Some(t) = self.engine.body_keep(&b.commit, &tid, &ak)?.at_most else { return Ok(Some((AtMost::Live(tid, ak), None))) };
        if self.engine.body_live(&b.commit, &tid, &ak).unwrap_or(true) {
            return Ok(Some((AtMost::Dead(tid, ak), None)));
        }
        Ok(Some((AtMost::Dead(tid, ak), self.state.entries.get(&(*l, *id)).cloned().map(|e| (e, t)))))
    }

    /// Re-seals decided at the end of a complete pass of the actor's labels (spec/permissions.md
    /// §3): members seen without a box at a current epoch (`Engine::reseal_due`) and members
    /// whose node's heartbeat under the label reports it stranded (§4); delivered by inbox and
    /// placed under the actor's labels like any membership commit.
    fn reseal(&mut self, g: &Tid, w: &Work) -> Result<()> {
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
        // (`Work::beats`)
        let beats: Vec<(Tid, CommitId)> = w.beats.iter().filter_map(|(n, s)| s.iter().next_back().map(|(_, c)| (*n, *c))).collect();
        for (node, c) in beats {
            if self.resealed.contains(&c) || !self.engine.get_typed(&node, &ct::SEEN)?.is_some_and(|s| s.stranded) {
                continue;
            }
            self.resealed.insert(c);
            // the member of the actor the node reads through: itself or up its owner chain
            let members: BTreeSet<Tid> = self.engine.core.current_members(&a).into_iter().map(|x| x.0).collect();
            // a node that may not re-seal that member leaves it to one that may
            let member = self.engine.owner_chain(&node).find(|t| members.contains(t));
            if let Some(t) = member
                && let Ok(done) = self.engine.reshare(&a, &t)
            {
                self.take_done(done)?;
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
        let mut w = Work::fresh();
        self.rebuild(&g, l, &mut w);
        let snaps: Snaps = w.snaps.iter().map(|(k, v)| (k.clone(), v.iter().map(|(_, c)| *c).collect())).collect();
        let fetching = w.unopened.iter().any(|b| self.fetching(b));
        let (unsettled, snapping) = self.unsettled_sets(!w.unopened.is_empty(), fetching)?;
        v.unsettled = unsettled.iter().cloned().collect();
        let mut note = Note::default();
        for b in &bodies {
            if let Some(needed) = self.must_hold(b, &snaps, &snapping, &mut note)? {
                v.must_hold.push((b.commit, needed));
            }
        }
        let desired = desired(&bodies);
        let entries: Vec<(BlobId, Entry)> = self.state.label_entries(l).map(|(b, e)| (b, e.clone())).collect();
        let at = At { g, l: *l, server: Some(*server), keys: &keys, snaps: &snaps, settled: unsettled.is_empty() };
        for (id, e) in entries {
            if let Fate::Delete(why, _) = self.deletable(&at, &id, &e, &desired, false, &mut note)? {
                v.must_not.push((id, format!("{why:?}")));
            }
        }
        Ok(Some(v))
    }

    /// The bodies label `l` of `g` should hold: the closure's; under a replaced label
    /// membership-class ones only (spec/sync.md §2: its content entries go).
    pub(super) fn bodies_under(&mut self, g: &Tid, l: &LabelId) -> Result<Vec<Body>> {
        let mut bodies = self.engine.label_bodies_meta(g)?;
        if self.is_replaced(g, l) {
            bodies.retain(|b| b.membership);
        }
        Ok(bodies)
    }

    pub(crate) fn is_replaced(&mut self, g: &Tid, l: &LabelId) -> bool {
        self.engine.labels_of(g).iter().any(|x| x.id == *l && x.replaced)
    }

    /// Entries present at `server` that unwrap under a held read secret and were never opened:
    /// opened now, or fetched again when their bytes are not here (a fetch lost to a cut or
    /// crash, secrets that arrived later).
    fn refetch(&mut self, conn: ConnId, server: ServerKey, l: LabelId, w: &Work, out: &mut Vec<super::Action>) -> Result<()> {
        let missing = |s: &Self, b: &BlobId| s.conns.get(&conn).is_some_and(|c| c.req.missing.contains(b));
        let ids: Vec<BlobId> = w.unopened.iter().filter(|b| !self.fetching(b) && !missing(self, b) && self.state.is_present(&server, &l, b)).copied().collect();
        let (held, want): (Vec<BlobId>, Vec<BlobId>) = ids.into_iter().partition(|b| self.engine.has_blob(b));
        // bytes here but never opened under the secrets held now
        if !held.is_empty() {
            self.open_entries(l, &held)?;
        }
        self.fetch_on(conn, l, want, out)
    }

    /// Prefix vs header for commit blobs whose header lists went by link (spec/commits.md §4):
    /// checked once the applied header is resolved, before the entry counts as holding its
    /// body; a disagreeing blob is bad input (`Kind::Bad`) and the body is judged missing there.
    fn check_linked_prefixes(&mut self, l: LabelId, scope: &Scope) -> Result<()> {
        type Parts = Vec<(usize, usize)>;
        let commits: Vec<CommitId> = match scope {
            Scope::All => self.state.label_commits(&l).collect(),
            Scope::Some { commits, .. } => commits.iter().copied().collect(),
        };
        let mut todo: Vec<(BlobId, CommitId, Parts)> = Vec::new();
        for c in commits {
            if !self.engine.header(&c).is_some_and(|h| osis_commit::ListField::ALL.iter().any(|f| h.links.get(*f).is_some())) {
                continue;
            }
            for (b, e) in self.state.entries_of(&l, &c) {
                if let Kind::Commit { parts, .. } = &e.kind
                    && !self.prefix_checked.contains(&b)
                {
                    todo.push((b, c, parts.clone()));
                }
            }
        }
        todo.sort_by_key(|x| x.0);
        for (b, c, parts) in todo {
            let Some(bytes) = self.engine.blob(&b)? else { continue };
            let Some(h) = self.engine.header(&c) else { continue };
            self.prefix_checked.insert(b);
            let agrees = match (osis_label::Prefix::parse(&bytes), osis_commit::prefix_inputs(&h, &parts)) {
                (Ok(p), Ok((expiry, keys))) => parts.is_empty() || p.agrees(expiry.map(WallMs), &h.blind, &keys),
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
    /// applied (`unopened`: a snapshot not fetched or applied yet, spec/sync.md §6: may-hold).
    pub(super) fn unsettled_of(&mut self, unopened: bool) -> Result<Unsettled> {
        Ok(self.unsettled_sets(unopened, false)?.0)
    }

    /// `unsettled_of`, and the aspects where a body is not established uncovered yet (spec/sync.md
    /// §6), so not must-hold: those of pending snapshots (pages not fetched, deltas missing), and
    /// every aspect (`None`) while an entry of the label that opens under a held secret is being
    /// fetched (`fetching`; it may be a snapshot). Other pending commits settle nothing there (two
    /// writers' pending commits otherwise withheld exactly what the other waited for), nor do
    /// entries that do not open as a commit or whose bytes no server delivers.
    pub(super) fn unsettled_sets(&mut self, unopened: bool, fetching: bool) -> Result<(Unsettled, Unsettled)> {
        let (mut all, mut snaps) = (BTreeSet::new(), BTreeSet::new());
        for (c, r) in self.engine.pending() {
            if r == crate::Reason::Parked {
                continue;
            }
            let Some(bytes) = self.engine.commit_bytes(&c)? else { continue };
            let Ok(cb) = osis_commit::CommitBlob::decode(&bytes) else { continue };
            let aspects = cb.header.aspects.iter().map(|a| Some((a.tid, a.ak.clone())));
            if is_snapshot(cb.header.kind) {
                snaps.extend(aspects.clone());
            }
            all.extend(aspects);
        }
        if unopened {
            all.insert(None);
        }
        if fetching {
            snaps.insert(None);
        }
        Ok((all, snaps))
    }

    /// Deposited commit entries at `server` a writer may promote now: past this node's wait
    /// (`RELAY_MIN_MS`: a co-writer may promote it first), not in flight, never a heartbeat.
    fn due_deposits(&mut self, conn: ConnId, server: ServerKey, l: LabelId) -> Vec<Deposit> {
        let ids: Vec<(BlobId, Entry)> = self.state.deposited_at(&server, &l).into_iter().filter_map(|b| self.state.entries.get(&(l, b)).map(|e| (b, e.clone()))).collect();
        let raw = self.raw_now();
        self.deposit_seen.retain(|k, _| self.state.deposited.contains(k));
        let mut out = Vec::new();
        for (id, e) in ids {
            if self.conns.get(&conn).is_some_and(|c| super::in_flight(&c.req.sent, (l, id), raw)) {
                continue;
            }
            let seen = *self.deposit_seen.entry((server, l, id)).or_insert(raw);
            let due = seen.saturating_add(self.relay_delay(&id.0));
            if raw < due {
                self.settle_by(due);
                continue;
            }
            let Kind::Commit { commit, parts, .. } = &e.kind else { continue };
            let Some(h) = self.engine.header(commit) else { continue };
            if h.aspects.iter().any(|a| a.ak.as_str() == "/seen") {
                continue;
            }
            let (commit, parts) = (*commit, parts.clone());
            out.push((id, e, commit, parts));
        }
        out
    }

    /// A promoter completes the chain it holds (spec/sync.md §5; spec/permissions.md §4): for
    /// each deposit due for promotion whose commit this writer applied, the parts of its
    /// author's chain no entry under `l` holds go up as this node's certificate copies, when it
    /// holds them all (else the deposit stays unpromoted).
    fn complete_chains(&mut self, conn: ConnId, server: ServerKey, g: &Tid, l: LabelId) -> Result<()> {
        for (_, _, c, parts) in self.due_deposits(conn, server, l) {
            let Some(missing) = self.chain_missing(server, g, l, &c, &parts)? else { continue };
            let mut bodies = Vec::new();
            let mut whole = true;
            for (x, p) in &missing {
                let bs = self.engine.part_bodies(x, p)?;
                let got: BTreeSet<(usize, usize)> = bs.iter().flat_map(|b| b.parts.iter().copied()).collect();
                whole &= p.is_subset(&got);
                bodies.push((*x, p.clone(), bs));
            }
            if !whole {
                continue;
            }
            for (x, p, bs) in bodies {
                for b in bs {
                    self.place(g, l, &b, true)?;
                }
                self.place_linked(l, &x, &p)?;
                self.state.add_cert(l, x);
            }
        }
        Ok(())
    }

    /// A writer re-uploads stamped the deposited entries it verified (spec/sync.md §5): applied
    /// commits whose author's chain is under the label (`complete_chains` placed what it held
    /// of it), never a heartbeat; per server (a blob may be deposited at several).
    fn promote(&mut self, conn: ConnId, server: ServerKey, g: &Tid, l: LabelId, write: &osis_crypto::SigningSecret, uploads: &mut Vec<osis_proto::Entry>) -> Result<()> {
        for (id, mut e, c, parts) in self.due_deposits(conn, server, l) {
            if uploads.iter().any(|u| osis_label::blob_id(&u.blob) == id) || !self.chain_missing(server, g, l, &c, &parts)?.is_some_and(|m| m.is_empty()) {
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

    /// The parts of the author's chain for `parts` of commit `c` (`Engine::author_chain`) that
    /// no entry under `l` holds at `server` (`held_parts_at`: the promotion or deletion is
    /// that server's); `None` when this node has not applied `c`.
    fn chain_missing(&mut self, server: ServerKey, g: &Tid, l: LabelId, c: &CommitId, parts: &[(usize, usize)]) -> Result<Option<BTreeMap<CommitId, Parts>>> {
        let Some(chain) = self.engine.author_chain(c, &parts.iter().copied().collect()) else { return Ok(None) };
        let closure = self.engine.closure(g);
        let mut out = BTreeMap::new();
        for (x, want) in chain {
            let (_, held) = self.held_parts_at(g, l, &x, &[server])?;
            // closure bodies carry what is on the label's own things
            let inside = self.engine.header(&x).map(|h| inside(&h, &closure)).unwrap_or_default();
            let missing: Parts = want.difference(&held).filter(|(ai, _)| !inside.contains(ai)).copied().collect();
            if !missing.is_empty() {
                out.insert(x, missing);
            }
        }
        Ok(Some(out))
    }

    /// This node's wait before relaying another node's blob `key` (`RELAY_MIN_MS` to
    /// `SETTLE_MS`, fixed per node and blob, so co-writers draw different points).
    fn relay_delay(&self, key: &[u8]) -> u64 {
        let mut h = osis_base::hash::Hasher::new();
        h.update(b"osis relay wait").update(self.engine.tid().as_bytes()).update(key);
        let mut x = [0u8; 8];
        h.finalize_xof(&mut x);
        RELAY_MIN_MS + u64::from_le_bytes(x) % (SETTLE_MS - RELAY_MIN_MS)
    }

    /// Whether this node uploads or relays commit `c` at a server lacking it now: its own (made
    /// here, a held key actor's included, or placed first by a flow) at once, another node's once `relay_delay` has passed since it
    /// arrived here (else a wake is set for then).
    fn relay_due(&mut self, c: &CommitId) -> bool {
        let me = self.engine.tid();
        let Some(m) = self.engine.core.ix.commits.get(c) else { return true };
        if m.origin == crate::events::Origin::Local || m.header.author == me || self.first.contains(c) {
            return true;
        }
        let due = m.received.0.saturating_add(self.relay_delay(&c.0));
        let now = self.now();
        if now >= due {
            return true;
        }
        let at = self.raw_now().saturating_add(due - now);
        self.settle_by(at);
        false
    }

    /// Whether this node placed the entry (its certificates, heartbeats, membership writes).
    fn mine(&self, e: &Entry) -> bool {
        e.cert || matches!(&e.kind, Kind::Commit { commit, .. } if self.own(commit))
    }

    /// A non-writer deposits its own membership writes (an invite grant, a self-removal,
    /// spec/sync.md §3).
    fn may_deposit(&self, keys: &HeadKeys, b: &Body) -> bool {
        keys.deposit.is_some() && b.membership && self.own(&b.commit)
    }

    /// Must-hold for a closure body (spec/sync.md §6): before its keep-at-least bound, or
    /// established uncovered by the label's snapshots. Must-hold: the parts a blob of the commit
    /// must hold to hold the body (all of them before keep-at-least, else those of the aspects
    /// no snapshot covers).
    fn must_hold(&mut self, b: &Body, snaps: &Snaps, unsettled: &Unsettled, note: &mut Note) -> Result<Option<Vec<(usize, usize)>>> {
        let Some(h) = self.engine.header(&b.commit) else { return Ok(None) };
        let aspects: Vec<(Tid, Ak)> = b.parts.iter().filter_map(|(ai, _)| h.aspects.get(*ai)).map(|a| (a.tid, a.ak.clone())).collect();
        let now = self.now();
        let mut before = false;
        if let Some((t, a)) = aspects.first() {
            let at_least = self.engine.body_keep(&b.commit, t, a)?.at_least;
            before = at_least > now;
            if before {
                note.at(at_least);
            }
        }
        let mut covered = !aspects.is_empty();
        let mut needed = Vec::new();
        for (p, (t, a)) in b.parts.iter().zip(&aspects) {
            let mut c = false;
            for s in snaps.get(&(*t, a.clone())).into_iter().flatten() {
                if *s != b.commit && self.covered_noted(s, &b.commit, t, a, note)? == Some(true) {
                    // covered-equal snapshots: the one with the higher commit ID goes
                    if is_snapshot(h.kind) && self.covered_noted(&b.commit, s, t, a, note)? == Some(true) && b.commit < *s {
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
    pub(super) fn parts_covered_at(&mut self, l: &LabelId, c: &CommitId, h: &osis_commit::Header, parts: &[(usize, usize)]) -> Result<bool> {
        let mut snaps: BTreeMap<(Tid, Ak), Vec<CommitId>> = BTreeMap::new();
        for (ai, _) in parts {
            let Some(a) = h.aspects.get(*ai) else { continue };
            let k = (a.tid, a.ak.clone());
            let on: Vec<CommitId> = self.engine.core.ix.by_aspect.get(&k).into_iter().flatten().map(|x| x.1).filter(|s| self.engine.header(s).is_some_and(|x| is_snapshot(x.kind)) && self.state.entries_of(l, s).next().is_some()).collect();
            snaps.insert(k, on);
        }
        self.parts_covered(&snaps, c, h, parts, &mut Note::default())
    }

    /// `Engine::covered`, noting an answer not established yet (`Note::unsure`: it may become
    /// one without a trigger).
    fn covered_noted(&mut self, s: &CommitId, c: &CommitId, t: &Tid, a: &Ak, note: &mut Note) -> Result<Option<bool>> {
        let r = self.engine.covered(s, c, t, a)?;
        note.unsure |= r.is_none();
        Ok(r)
    }

    /// Whether every part's aspect of commit `c` is covered by a snapshot under the label
    /// (`snaps`).
    fn parts_covered(&mut self, snaps: &Snaps, c: &CommitId, h: &osis_commit::Header, parts: &[(usize, usize)], note: &mut Note) -> Result<bool> {
        for (ai, _) in parts {
            let Some(a) = h.aspects.get(*ai) else { return Ok(false) };
            let mut ok = false;
            for s in snaps.get(&(a.tid, a.ak.clone())).into_iter().flatten() {
                if s != c && self.covered_noted(s, c, &a.tid, &a.ak, note)? == Some(true) {
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

    /// Whether an entry of commit `c` holding `parts` is present at `server` under `l` (any
    /// entry when `None`: this node's own served state), checked genuine: a forged blob listing
    /// the parts holds nothing, nor a must-not-hold one (`holds_nothing`).
    fn carried_by(&mut self, server: Option<&ServerKey>, g: &Tid, l: &LabelId, c: &CommitId, parts: &[(usize, usize)]) -> bool {
        let ids: Vec<BlobId> = self.state.entries_of(l, c).filter(|(id, e)| !e.cert && matches!(&e.kind, Kind::Commit { parts: p, .. } if parts.iter().all(|x| p.contains(x)) && !self.holds_nothing(g, c, p)) && server.is_none_or(|s| self.state.is_present(s, l, id))).map(|(id, _)| id).collect();
        ids.into_iter().any(|id| self.genuine(&id))
    }

    /// Whether a blob of commit `c` with delta set `parts` under a label of `g` is must-not-hold
    /// whatever its siblings: it holds a delta this node dropped (purge, expiry, keep-at-most,
    /// compaction) or one the label's actor may not read (outside the required set). It holds
    /// no body and makes no other blob a strict subset (spec/sync.md §6).
    fn holds_nothing(&self, g: &Tid, c: &CommitId, parts: &[(usize, usize)]) -> bool {
        let Some(m) = self.engine.core.ix.commits.get(c) else { return false };
        let x = self.engine.group_actor(g);
        parts.iter().any(|p| m.dropped.contains(p) || m.header.aspects.get(p.0).is_some_and(|a| !self.engine.core.may_read(&x, &self.engine.core.reader_of(&a.tid))))
    }

    /// The genuine entry under `l` holding exactly this body, not tombstoned at `server`, whoever
    /// placed it (a certificate copy of the same parts holds it too: other nodes see one entry).
    /// One present at `server` first: the label then holds the body (spec/sync.md §6), and
    /// uploading another encryption (this node's own, whose upload was lost) would only add a
    /// duplicate for the tiebreak of §7 to delete. `None`: any entry (this node's served state).
    fn entry_for(&mut self, server: Option<&ServerKey>, l: &LabelId, b: &Body) -> Option<BlobId> {
        let mut ids: Vec<BlobId> = self.state.entries_of(l, &b.commit).filter(|(id, e)| matches!(&e.kind, Kind::Commit { parts, .. } if *parts == b.parts) && server.is_none_or(|s| !self.state.gone.contains(&(*s, *l, *id)))).map(|(id, _)| id).collect();
        if let Some(server) = server {
            ids.sort_by_key(|id| !self.state.is_present(server, l, id));
        }
        ids.into_iter().find(|id| self.genuine(id))
    }

    /// Whether every delta of commit blob `id` hashes to its header entry (spec/commits.md §4;
    /// `Engine::parts_genuine`). Opening a blob checks its prefix, not its deltas, and a held
    /// commit's late parts are skipped unchecked, so an entry's parts are only its own claim
    /// until this says yes. A forged blob is marked `Bad` under every label; unknown yet (a
    /// thing's `/created` missing) counts as no.
    pub(crate) fn genuine(&mut self, id: &BlobId) -> bool {
        if let Some(v) = self.genuine.get(id) {
            return *v;
        }
        let Some(key) = self.state.blobs.get(id).map(|r| r.key.clone()) else { return false };
        let Ok(Some(bytes)) = self.engine.blob(id) else { return false };
        let verdict = match crate::labeling::open_commit(&bytes, &key) {
            Ok((_, c)) => self.engine.parts_genuine(&c),
            Err(_) => Some(false),
        };
        let Some(v) = verdict else { return false };
        self.genuine.insert(*id, v);
        if !v {
            let ls: Vec<LabelId> = self.state.labels_of(id);
            for l in ls {
                if let Some(mut e) = self.state.entries.get(&(l, *id)).cloned() {
                    e.kind = Kind::Bad;
                    self.state.set_entry(l, *id, e);
                }
            }
            self.diag(format!("blob {id:?}: a delta does not match its header"));
        }
        v
    }

    /// Places a body under `l`: an encryption of it this node holds (never a certificate
    /// copy's, never one tombstoned there), else a fresh one; wrapped for the label.
    fn place(&mut self, g: &Tid, l: LabelId, b: &Body, cert: bool) -> Result<Option<BlobId>> {
        let Some(secret) = self.engine.wrap_secret(g, Some((&b.commit, &b.parts)))? else { return Ok(None) };
        let reuse = if cert { None } else { self.state.blob_for(&b.commit, &b.parts, |id| self.state.is_gone(&l, id) || self.state.entries.contains_key(&(l, *id))) };
        let (id, key) = match reuse.and_then(|id| self.state.blobs.get(&id).map(|r| (id, r.key.clone()))) {
            Some(x) => x,
            None => {
                let pt = self.engine.body_plaintext(b)?;
                if pt.is_empty() {
                    return Ok(None);
                }
                let s = seal_body(&Body { plaintext: pt, ..b.clone() }, &mut *self.rng)?;
                self.engine.put_blobs(vec![(s.id, s.blob)])?;
                self.state.add_blob(s.id, BlobRec { commit: b.commit, parts: b.parts.clone(), key: s.key.clone(), cert });
                (s.id, s.key)
            }
        };
        let Some(salt) = self.engine.blob(&id)?.and_then(|x| osis_label::Prefix::parse(&x).ok()).map(|p| *p.salt()) else { return Ok(None) };
        let wrap = osis_crypto::wrap(&secret, &id, &key)?;
        self.state.set_entry(l, id, Entry { wrap, stamp: None, cert, kind: Kind::Commit { commit: b.commit, parts: b.parts.clone(), salt } });
        Ok(Some(id))
    }

    /// Chunk, page and header-list blobs a commit references that this node holds.
    fn chunk_blobs(&mut self, c: &CommitId) -> Result<Vec<BlobId>> {
        Ok(self.engine.package(c)?.map(|p| p.blobs.into_iter().map(|(id, _)| id).collect()).unwrap_or_default())
    }

    /// Blobs the body's own delta values link (trees of large values, pages), listed by its
    /// commit or not: reused chunks and a snapshot's values belong to the closure too
    /// (spec/sync.md §3), so a reader under a new label (replacement, a move) gets them. Those
    /// held here or already an entry under `l`; the walk is cached per body once complete.
    fn body_blobs(&mut self, l: &LabelId, b: &Body, left: &mut Left) -> Result<Vec<BlobId>> {
        let key = (b.commit, b.parts.clone());
        let all = match self.body_links.get(&key) {
            Some(x) => x.clone(),
            None => {
                let pt = self.engine.body_plaintext(b)?;
                let r = self.engine.body_links(&pt)?;
                let all: Vec<BlobId> = r.blobs.into_iter().collect();
                if r.missing.is_empty() {
                    self.body_links.insert(key, all.clone());
                } else {
                    // the walk goes on once the missing nodes are here
                    for m in r.missing {
                        left.links.entry(m).or_default().insert(b.commit);
                    }
                }
                all
            }
        };
        let (here, not): (Vec<BlobId>, Vec<BlobId>) = all.into_iter().partition(|id| self.state.entries.contains_key(&(*l, *id)) || self.engine.has_blob(id));
        for id in not {
            left.links.entry(id).or_default().insert(b.commit);
        }
        Ok(here)
    }

    /// A grantee device places a certificate copy of what its inbox (label `l` of `g`) brought,
    /// once applied, under that label: every part the inbox blob carried (its boxes included,
    /// sealed to the actor anyway), with the `/label` and `/created` commits of the things it
    /// named, so the actor's other devices find the grant and its labels there (spec/sync.md
    /// §3); not what an entry there already holds (each member of a group actor reads its inbox
    /// and placed the same copy again). The consumed inbox blob stays until it expires: its label hints are what a later
    /// member that cannot apply the copied `/label` yet (the granter's chain pending) opens the
    /// thing's label by.
    fn inbox_copies(&mut self, g: &Tid, l: LabelId) -> Result<()> {
        // only under the actor's home label (spec/sync.md §3): an inbox at another group's label
        // would show that group's readers the actor's edges, labels and box keys
        if self.engine.core.secret_actor(g) != Some(*g) || !self.inbox_actors(&l).contains(g) {
            return Ok(());
        }
        let opened: Vec<(BlobId, CommitId)> = self.state.label_entries(&l).filter_map(|(b, e)| if let Kind::Inbox(Some(c)) = e.kind { Some((b, c)) } else { None }).collect();
        for (b, c) in opened {
            if self.state.certs.contains(&(l, c)) || self.engine.core.ix.pending.contains_key(&c) {
                continue;
            }
            let Some(m) = self.engine.core.ix.commits.get(&c).cloned() else { continue };
            let Some((ais, things)) = self.inbox_parts(&l, &b)? else { continue };
            // a valid commit only, and labels only of things it touches (the payload's list is
            // the sender's word: it could name any thing this device holds)
            if !ais.iter().all(|ai| m.valid.get(*ai).copied().unwrap_or(false)) {
                continue;
            }
            // another member's copy is there: done, as if placed here
            if self.held_whole(g, l, &c, &ais)? {
                self.state.add_cert(l, c);
                continue;
            }
            let touched: BTreeSet<Tid> = m.header.aspects.iter().map(|a| a.tid).collect();
            for t in things.into_iter().filter(|t| touched.contains(t)) {
                for ak in ["/created", "/label"] {
                    let Some((x, xs)) = self.engine.aspect_commit(&t, ak) else { continue };
                    if !self.state.certs.contains(&(l, x)) && !self.held_whole(g, l, &x, &xs)? {
                        self.place_certificate_in(g, &x, &xs)?;
                    }
                }
            }
            self.place_certificate_in(g, &c, &ais)?;
        }
        Ok(())
    }

    /// This node's chain certificates and node card under `l` (spec/permissions.md §4): the
    /// aspects no entry under the label holds yet, as a fresh encryption per label. Another
    /// node's entry counts only when this node checked it genuine (`genuine`), it is present at
    /// every server this node syncs the label with (the decision is the label's, not one
    /// server's), and a newcomer can open it: one granted after a rotation gets the history
    /// boxes with its grant (spec/crypto.md §4) and opens entries under older epochs like the
    /// label's older content, except a rotation commit of the label's actor, which is wrapped
    /// under the epoch it supersedes (spec/crypto.md §5): such an entry counts only when it
    /// opens under the newest read secret. Returns the commits whose copies wait (`hold`).
    fn certificates(&mut self, g: &Tid, l: LabelId, revokes_only: bool, authors: &BTreeSet<Tid>) -> Result<BTreeSet<CommitId>> {
        let closure = self.engine.closure(g);
        let wanted = if revokes_only {
            // under an epoch a departure inside a member leaves uncovered: those revokes only
            let actor = self.engine.group_actor(g);
            self.engine.inside_member_revokes(&actor, &closure)
        } else {
            let mut wanted = self.card_certificates(g);
            // revokes and roster snapshots about authors seen under the label (spec/permissions.md
            // §4), so its verifiers judge their writes as this node does: authors of an entry
            // judged invalid here or not judged yet (`Engine::judged_valid`); a revoke changes no
            // verdict on the writes its frontier covers (a joiner's home label holds the copy of its grant by
            // link actor L, made before L's removal)
            // (`authors`: `Work::unjudged`)
            let me = self.engine.tid();
            let mut authors = authors.clone();
            authors.remove(&me);
            for (c, p) in self.engine.revoke_certificates(&authors, &closure) {
                wanted.entry(c).or_default().extend(p);
            }
            wanted
        };
        let mut held = BTreeSet::new();
        for (c, want) in wanted {
            let (mine, have) = self.held_parts(g, l, &c)?;
            // what the label's closure bodies carry is never copied (a copy duplicating closure
            // parts is a strict subset others delete)
            let inside = self.engine.header(&c).map(|h| inside(&h, &closure)).unwrap_or_default();
            let missing: BTreeSet<(usize, usize)> = want.difference(&have).filter(|(ai, _)| !inside.contains(ai)).copied().collect();
            // this node's own copy placed before and gone since (deleted at the server): not
            // placed again, but for its own card while it reads the label's actor (admins delete
            // a departed node's card; a re-grant wants it back, spec/permissions.md §4)
            if missing.is_empty() || mine.is_empty() && self.state.certs.contains(&(l, c)) && !self.own_card_read(g, &c, &missing) {
                continue;
            }
            // another node's demotion or new `/keys` received less than `SETTLE_MS` ago is its
            // author's to place (spec/permissions.md §3, §4): members that learn of it under
            // another label first do not all copy it; a wake brings the pass back then
            let me = self.engine.tid();
            let now = self.now();
            let due = self.engine.core.ix.commits.get(&c).filter(|m| m.header.author != me).map(|m| m.received.0.saturating_add(SETTLE_MS)).filter(|t| *t > now);
            if let Some(t) = due
                && let Some(h) = self.engine.header(&c)
                && (h.frontier.is_some() || missing.iter().all(|(ai, _)| h.aspects.get(*ai).is_some_and(|a| a.ak.as_str() == "/keys")))
            {
                let at = self.raw_now().saturating_add(t - now);
                self.settle_by(at);
                continue;
            }
            // a copy of this node's commit waits for the commit under its things' labels
            // (spec/sync.md §5)
            if !self.under_own_label(g, &c) && self.hold(&c)? {
                held.insert(c);
                continue;
            }
            for b in self.engine.part_bodies(&c, &missing)? {
                self.place(g, l, &b, true)?;
            }
            self.place_linked(l, &c, &missing)?;
            self.state.add_cert(l, c);
        }
        Ok(held)
    }

    /// Whether `parts` of `c` are this node's own card (its `/node`, `/reach`, `/keys` writes)
    /// and it currently reads `g`'s actor.
    fn own_card_read(&self, g: &Tid, c: &CommitId, parts: &BTreeSet<(usize, usize)>) -> bool {
        let me = self.engine.tid();
        let Some(h) = self.engine.header(c) else { return false };
        h.author == me && parts.iter().all(|(ai, _)| h.aspects.get(*ai).is_some_and(|a| a.tid == me && is_card(a.ak.as_str()))) && self.engine.core.may_read(&me, &self.engine.group_actor(g))
    }

    /// Whether entries under `l` already hold every delta of `c` on aspects `ais` (another
    /// member's copy of the same grant counts: spec/permissions.md §4), so a copy would only be
    /// a duplicate.
    fn held_whole(&mut self, g: &Tid, l: LabelId, c: &CommitId, ais: &BTreeSet<usize>) -> Result<bool> {
        let Some(h) = self.engine.header(c) else { return Ok(false) };
        let want = parts_of(&h, |i| ais.contains(&i));
        let (_, held) = self.held_parts(g, l, c)?;
        Ok(want.is_subset(&held))
    }

    /// The parts of commit `c` entries under `l` hold, as (this node's certificate copies, all
    /// that count): another node's copy or body counts once genuine and present at every server
    /// this node syncs the label with, and, carrying a rotation of the label's actor, only if it
    /// opens under the newest read secret (spec/permissions.md §4). Not `held_at` (whether this
    /// node's own commit is placed).
    fn held_parts(&mut self, g: &Tid, l: LabelId, c: &CommitId) -> Result<(Parts, Parts)> {
        let servers: Vec<ServerKey> = self.conns.values().filter(|x| x.labels.contains_key(&l)).map(|x| x.server).collect();
        self.held_parts_at(g, l, c, &servers)
    }

    /// `held_parts` with another node's entries counted when present at each of `servers`.
    fn held_parts_at(&mut self, g: &Tid, l: LabelId, c: &CommitId, servers: &[ServerKey]) -> Result<(Parts, Parts)> {
        let newest = self.engine.wrap_secret(g, None)?;
        let mut mine: BTreeSet<(usize, usize)> = BTreeSet::new();
        let mut others: Vec<(BlobId, Vec<(usize, usize)>)> = Vec::new();
        for (id, e) in self.state.entries_of(&l, c) {
            let Kind::Commit { parts, .. } = &e.kind else { continue };
            if e.cert {
                mine.extend(parts.iter().copied());
            } else if !servers.is_empty()
                && servers.iter().all(|s| self.state.is_present(s, &l, &id))
                && (!self.engine.carries_secrets(g, c, parts) || newest.as_ref().is_some_and(|k| osis_crypto::unwrap(k, &id, &e.wrap).is_ok()))
            {
                others.push((id, parts.clone()));
            }
        }
        let mut held = mine.clone();
        for (id, parts) in others {
            if self.genuine(&id) {
                held.extend(parts);
            }
        }
        Ok((mine, held))
    }

    /// Whether this node may rotate the read role of `g`'s secret actor (spec/permissions.md §3).
    fn may_rotate_read(&self, g: &Tid) -> bool {
        let me = self.engine.tid();
        let a = self.engine.core.secret_actor(g).unwrap_or(*g);
        crate::rotation::may_rotate(&self.engine.core, &me, &a).contains(&Role::Read)
    }

    /// A heartbeat under `l` at most once per `HEARTBEAT_MIN_INTERVAL` (spec/permissions.md §4),
    /// skipped by deposit when the budget is tight.
    fn heartbeat(&mut self, g: &Tid, l: LabelId, keys: &HeadKeys, tight: bool) -> Result<()> {
        if !self.cfg.heartbeats {
            return Ok(());
        }
        let now = self.now();
        if self.state.beats.get(&l).is_some_and(|t| t.saturating_add(HEARTBEAT_MIN_INTERVAL_MS) > now) {
            return Ok(());
        }
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
            && let Some(c) = self.engine.core.ix.by_aspect.get(&(me, Ak::new("/seen").map_err(|_| crate::Error::Misuse("ak"))?)).and_then(|s| s.iter().next_back()).map(|x| x.1)
            && let Some(h) = self.engine.header(&c)
            && h.ts.wall_ms().0.saturating_add(HEARTBEAT_MIN_INTERVAL_MS) > now
            && self.engine.get_typed(&me, &ct::SEEN).ok().flatten().is_some_and(|s| !s.stranded)
        {
            return Ok(Some(c));
        }
        // `ts` of the commit: the HLC's next wall time (spec/permissions.md §4)
        let ts = now.max(self.engine.core.hlc.last().wall_ms().0);
        let life = self.cfg.heartbeat_lifetime_ms.clamp(osis_base::format::HEARTBEAT_MIN_LIFETIME_MS, osis_base::format::HEARTBEAT_MAX_LIFETIME_MS);
        let mut m = crate::Mutation::new();
        // whole: a field left to an earlier heartbeat would go when that one expires (spec/crdt.md §9)
        m.replace(me, &ct::SEEN, &ct::Seen { ts: WallMs(ts), stranded })?;
        m.expires(me, &ct::SEEN, WallMs(ts.saturating_add(life)))?;
        self.engine.commit(m)
    }

    /// A stranded heartbeat (spec/permissions.md §4; spec/sync.md §5): the label cannot be read
    /// here; deposited, wrapped under the newest established read secret held, no open needed.
    pub(crate) fn stranded(&mut self, conn: ConnId, g: Tid, l: LabelId, out: &mut Vec<super::Action>) -> Result<()> {
        if self.state.stranded.get(&l).is_some_and(|t| t.saturating_add(HEARTBEAT_MIN_INTERVAL_MS) > self.now()) {
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
        self.state.set_stranded(l, now);
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
        // a replaced label is never stepped again (spec/sync.md §2: its replacement carries on)
        if !self.step_due(&g, &l, &keys) {
            return Ok(false);
        }
        let (Some(write), Some(head)) = (keys.write.clone(), head) else { return Ok(false) };
        let a = self.engine.core.secret_actor(&g).unwrap_or(g);
        let core = &self.engine.core;
        let ids: Vec<CommitId> = core.ix.by_thing.get(&a).into_iter().flatten().filter(|c| core.ix.commits.get(c).is_some_and(|m| m.view.kind.is_membership())).copied().collect();
        let mut uploads = Vec::new();
        for id in ids {
            for b in self.engine.bodies(&id)? {
                if b.reader != a && !self.engine.core.may_read(&a, &b.reader) {
                    continue;
                }
                let bid = match self.entry_for(Some(&server), &l, &b) {
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
        // a child of the server's head already recorded in `/label` (this node's local step,
        // another admin's) is registered first: the walk down the recorded path issues nothing
        let (step, set) = match self.recorded_child(&g, &l, &head.id()) {
            Some(x) => x,
            None => {
                if !self.step_settled(&g) {
                    return Ok(false);
                }
                let (step, done) = self.engine.issue_step(&g, &l, &head.id(), false)?;
                self.take_done(done)?;
                let Some(x) = step else { return Ok(false) };
                x
            }
        };
        if let Some(lc) = self.lc_mut(conn, &l) {
            lc.registering = Some((step.clone(), set.clone()));
        }
        self.command(conn, Command::Register { label: l, step, claim_set: Some(set) }, out)?;
        Ok(true)
    }

    /// A child of step `head` recorded in `/label` with its claim set (the lowest ID among
    /// several).
    fn recorded_child(&mut self, g: &Tid, l: &LabelId, head: &osis_label::StepId) -> Option<(osis_label::Step, osis_label::ClaimSet)> {
        let gl = self.group_label(g, l)?;
        gl.steps.values().filter_map(|(s, c)| c.clone().map(|c| (s.clone(), c))).filter(|(s, _)| s.prev == Some(*head)).min_by_key(|(s, _)| s.id())
    }

    /// Facts about an entry under the label (spec/sync.md §6): `None` when this node cannot
    /// judge it (may-hold). `server` `None`: this node's own served state (every entry counts
    /// as present).
    fn judge(&mut self, at: &At, id: &BlobId, e: &Entry, desired: &Desired, note: &mut Note) -> Result<Option<Judged>> {
        let (g, l, server, snaps, settled) = (&at.g, &at.l, at.server.as_ref(), at.snaps, at.settled);
        let now = self.now();
        let Kind::Commit { commit, parts, .. } = &e.kind else { return Ok(None) };
        let Some(m) = self.engine.core.ix.commits.get(commit).cloned() else { return Ok(None) };
        let h = m.header.clone();
        // a blob expires whole with its class (spec/sync.md §3)
        if let Some(t) = parts.first().and_then(|(ai, _)| h.aspects.get(*ai)).and_then(|a| a.expires) {
            if t <= now {
                return Ok(Some((Hold::MustNot(Why::Expired), false, Vec::new())));
            }
            note.at(t);
        }
        let aspects: Vec<(Tid, Ak)> = parts.iter().filter_map(|(ai, _)| h.aspects.get(*ai)).map(|a| (a.tid, a.ak.clone())).collect();
        if parts.iter().any(|p| m.dropped.contains(p)) {
            // every delta's live writes count, the kept ones' too (spec/sync.md §7, `carried`)
            let live = parts.iter().any(|p| self.part_live(&h, commit, p));
            return Ok(Some((Hold::MustNot(Why::Dropped), live, aspects)));
        }
        if e.cert {
            return Ok(Some((Hold::May, false, aspects)));
        }
        let desired: Vec<&Vec<(usize, usize)>> = desired.get(commit).into_iter().flatten().collect();
        let mut f = Facts { required: false, closure: true, covered: None, ..Facts::default() };
        if desired.contains(&parts) {
            f.required = true;
            // the duplicate with the higher blob ID goes (spec/sync.md §7)
            // (only a genuine one: a forged duplicate must not get the real entry deleted)
            let lower: Vec<BlobId> = self.state.entries_of(l, commit).filter(|(b, o)| b < id && !o.cert && o.kind == e.kind && server.is_none_or(|s| self.state.is_present(s, l, b))).map(|(b, _)| b).collect();
            f.duplicate_higher = lower.into_iter().any(|b| self.genuine(&b));
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
                .entries_of(l, commit)
                .filter(|(b, _)| b != id && (server.is_none() || self.state.present_anywhere(l, b)))
                .filter_map(|(b, o)| match &o.kind {
                    // a must-not-hold superset counts for nothing
                    Kind::Commit { parts: p2, .. } if p2.len() > parts.len() && parts.iter().all(|p| p2.contains(p)) && !self.holds_nothing(g, commit, p2) => Some((b, p2.clone())),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .into_iter()
                // a forged superset holds nothing (it would get the real projection deleted)
                .filter(|(b, _)| self.genuine(b))
                .map(|(_, p2)| p2)
                .collect();
            // a superset whose extra deltas a snapshot under the label covers carries nothing
            // more: this projection is one a right holder dropped them from (spec/sync.md §7)
            let mut sup = false;
            for p2 in sups {
                let extra: Vec<(usize, usize)> = p2.into_iter().filter(|p| !parts.contains(p)).collect();
                if !self.parts_covered(snaps, commit, &h, &extra, note)? {
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
                // another node's card nobody needs any more goes (spec/permissions.md §4), and
                // a certificate copy nobody completes (`orphan`)
                if settled && (self.stale_card(at, commit, &h, parts) || self.orphan(at, id, commit, &h, parts, note)?) {
                    return Ok(Some((Hold::MustNot(Why::Outside), false, aspects)));
                }
                // other certificates (membership-class, node cards, heartbeats) are not ours to judge
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
        // a body outside the required set holds no write this label must keep
        let hold = classify(&f);
        Ok(Some((hold, hold != Hold::MustNot(Why::Outside), aspects)))
    }

    /// Unopened entries present at `server` under replaced label `l` that only content commits
    /// list (their chunks, tree nodes and pages): no membership-class commit or certificate
    /// kept there needs them (spec/sync.md §2). A blob no held commit lists stays.
    pub(crate) fn replaced_leftovers(&self, server: &ServerKey, l: &LabelId) -> Vec<BlobId> {
        let unknown: BTreeSet<BlobId> = self.state.present_at(server, l).into_iter().filter(|b| self.state.entries.get(&(*l, *b)).is_some_and(|e| e.kind == Kind::Unknown)).collect();
        if unknown.is_empty() {
            return Vec::new();
        }
        let core = &self.engine.core;
        // the commits listing each (`by_chunk`, their views)
        unknown
            .into_iter()
            .filter(|b| {
                let listers = core.ix.by_chunk.get(b).into_iter().flatten().filter_map(|c| core.ix.commits.get(c));
                let mut any = false;
                for m in listers {
                    if m.view.aspects.iter().any(|a| kept_when_replaced(a.ak.as_str())) {
                        return false;
                    }
                    any = true;
                }
                any
            })
            .collect()
    }

    /// Whether an entry of commit `c` holding `parts` is another node's card that no member
    /// needs (spec/permissions.md §4): every part is its author's `/node`, `/reach` or `/keys`,
    /// and each is superseded by a newer commit on that aspect present here under `l`, or, for
    /// `/node` and `/reach`, the node departed (a departed node is never dialed; its `/keys`
    /// stays while chains of its old writes may need it).
    fn stale_card(&mut self, at: &At, c: &CommitId, h: &osis_commit::Header, parts: &[(usize, usize)]) -> bool {
        let (g, l, server) = (&at.g, &at.l, at.server.as_ref());
        let me = self.engine.tid();
        let aks: BTreeSet<&str> = parts.iter().filter_map(|(ai, _)| h.aspects.get(*ai)).filter(|a| a.tid == h.author).map(|a| a.ak.as_str()).collect();
        let all_card = parts.iter().filter_map(|(ai, _)| h.aspects.get(*ai)).all(|a| a.tid == h.author && is_card(a.ak.as_str()));
        if h.author == me || aks.is_empty() || !all_card {
            return false;
        }
        // departed: it reads the actor no more, and an applied write removed an edge on its way
        // to the actor, or one there passed its `until`: its own, or that of an actor it reads
        // through (its person). A view lacking the node's chain holds no such write on its way
        // and proves nothing ("reads no more" alone misjudged such members, spec/sync.md §6)
        let actor = self.engine.group_actor(g);
        let core = &self.engine.core;
        let now = osis_base::Ts::make(WallMs(self.now()), 0).unwrap_or_default();
        let author = h.author;
        let departed = !core.may_read(&author, &actor)
            && core.timelines.get(&author).is_some_and(|tl| {
                tl.applied().keys().any(|w| match w {
                    osis_perm::WriteId::Op(x, i) => tl.membership_commit(x).and_then(|mc| mc.ops.get(*i as usize)).is_some_and(|op| {
                        let ended = op.edge.is_none_or(|e| !e.alive_at(Some(now)));
                        let way = (op.member == author || core.may_read(&author, &op.member)) && (op.target == actor || core.may_read(&op.target, &actor));
                        ended && way
                    }),
                    osis_perm::WriteId::Snapshot(_) => false,
                })
            });
        aks.into_iter().all(|ak| {
            if departed && ak != "/keys" {
                return true;
            }
            // newer: the node's own valid write, with an entry here checked genuine (anyone may
            // sign a commit writing another's card with a later `ts`)
            let Some(x) = self.engine.latest_by(&author, ak, Some(&author)) else { return false };
            if x == *c || !self.engine.header(&x).is_some_and(|n| n.ts > h.ts) {
                return false;
            }
            let ids: Vec<BlobId> = self.state.entries_of(l, &x).filter(|(id, _)| server.is_none_or(|s| self.state.is_present(s, l, id))).map(|(id, _)| id).collect();
            ids.into_iter().any(|id| self.genuine(&id))
        })
    }

    /// Whether entry `id` of commit `c` holding `parts`, outside the label's closure, is a
    /// certificate copy whose author no longer reads the label's actor and whose author's chain
    /// no entry under `l` at `server` completes: outside the required set (spec/sync.md §6),
    /// since nobody is obliged to complete it and a verifier would hold it pending for ever.
    /// Judged only on a commit this node applied (it knows the author and the chain), and not on
    /// a deposit there: promotion completes or leaves those (spec/sync.md §5).
    fn orphan(&mut self, at: &At, id: &BlobId, c: &CommitId, h: &osis_commit::Header, parts: &[(usize, usize)], note: &mut Note) -> Result<bool> {
        let (g, l) = (&at.g, &at.l);
        // this node's own served state: its chain completion runs at servers only
        let Some(server) = &at.server else { return Ok(false) };
        let actor = self.engine.group_actor(g);
        if h.author == self.engine.tid() || self.state.deposited.contains(&(*server, *l, *id)) || self.engine.core.may_read(&h.author, &actor) {
            return Ok(false);
        }
        // the chain's entries are other commits': judged again each pass
        note.unsure = true;
        Ok(self.chain_missing(*server, g, *l, c, parts)?.is_some_and(|m| !m.is_empty()))
    }

    /// Deletes must-not-hold entries present at the server, carriers first (spec/sync.md §6,
    /// §7); timed deletes for bodies under a relative keep-at-most (spec/commits.md §5). Judges
    /// the entries and bodies of `scope`; what waits goes into `left`.
    fn deletions(&mut self, conn: ConnId, at: &At, bodies: &[Body], scope: &Scope, left: &mut Left, out: &mut Vec<super::Action>) -> Result<()> {
        let (g, l, keys, settled) = (&at.g, at.l, at.keys, at.settled);
        let Some(server) = at.server else { return Ok(()) };
        let ids: Vec<BlobId> = match scope {
            Scope::All => self.state.present_at(&server, &l),
            Scope::Some { .. } => self.scope_entries(&l, scope).into_iter().filter(|b| self.state.is_present(&server, &l, b)).collect(),
        };
        self.stats.entries += ids.len() as u64;
        let desired = desired(bodies);
        // deletes in flight on this connection are not sent again (`RESEND_MS`)
        let raw = self.raw_now();
        let busy = |s: &Self, id: &BlobId| s.conns.get(&conn).is_some_and(|c| super::in_flight(&c.req.deleting, (l, *id), raw));
        let send = |s: &mut Self, id: BlobId| {
            if let Some(c) = s.conns.get_mut(&conn) {
                c.req.deleting.insert((l, id), raw);
            }
        };
        let mut items = Vec::new();
        let mut note = Note::default();
        for id in &ids {
            let id = *id;
            let Some(e) = self.state.entries.get(&(l, id)).cloned() else { continue };
            let Kind::Commit { commit, .. } = e.kind else { continue };
            let fate = self.deletable(at, &id, &e, &desired, true, &mut note)?;
            note.leave(commit, left);
            if !settled {
                left.held_back.insert(commit);
            }
            match fate {
                Fate::Keep | Fate::Wait => {}
                Fate::Expired => {
                    // the server drops it unattended (spec/sync.md §5)
                    self.absent_at(Some(server), l, id)?;
                }
                Fate::Delete(_, item) => {
                    left.commits.insert(commit);
                    if !busy(self, &id) {
                        send(self, id);
                        items.push(item);
                    }
                }
            }
        }
        // chunks of dropped deltas (spec/commits.md §5: a purge drops every body carrying the
        // values; spec/sync.md §3: chunk blobs belong to the closure): those listed by the
        // commits of `scope` and the chunk entries it names
        let cands = self.chunk_entries(&l, scope, |s, b| s.state.is_present(&server, &l, b));
        let (chunks, waiting) = self.dropped_chunks(&cands)?;
        left.blobs.extend(waiting);
        let wants: Vec<BlobId> = std::mem::take(&mut self.tree_wants).into_iter().filter(|b| self.state.is_present(&server, &l, b)).collect();
        self.fetch_on(conn, l, wants, out)?;
        for (id, chunk) in &chunks {
            left.blobs.insert(*id);
            if busy(self, id) {
                continue;
            }
            if let Some(item) = self.chunk_delete(conn, keys, &l, id, chunk, out)? {
                send(self, *id);
                items.push(item);
            }
        }
        // under a replaced label the chunk and page entries of content commits go with them
        // (spec/sync.md §2: only membership-class commits and certificates stay)
        if keys.delete.is_some() && self.is_replaced(g, &l) {
            for b in self.replaced_leftovers(&server, &l) {
                if busy(self, &b) {
                    continue;
                }
                if let Some(item) = delete_item(keys, &l, b, None, None, &[]) {
                    send(self, b);
                    items.push(item);
                }
            }
        }
        // the blobs certificate copies link (`place_linked`) once this node knows no entry of
        // their commit under the label any more (deleted; one placed and not confirmed yet still
        // counts), unless another present entry links them too (roster snapshots sharing tree
        // pages): nothing under the label needs them
        if keys.delete.is_some() {
            let copied = self.copies_in(&l, scope);
            let mut gone = BTreeSet::new();
            for b in self.copy_links(&l, copied)? {
                if self.state.is_present(&server, &l, &b) {
                    left.blobs.insert(b);
                    if !busy(self, &b) {
                        gone.insert(b);
                    }
                }
            }
            if !gone.is_empty() {
                let present = self.state.present_at(&server, &l);
                for b in self.linked_by(&l, present)? {
                    gone.remove(&b);
                }
            }
            for b in gone {
                if let Some(item) = delete_item(keys, &l, b, None, None, &[]) {
                    send(self, b);
                    items.push(item);
                }
            }
        }
        // timed deletes: bodies under a relative keep-at-most with a known bound
        for b in bodies {
            let Some(id) = self.entry_for(Some(&server), &l, b) else { continue };
            if !self.state.is_present(&server, &l, &id) || self.state.timed.contains(&(server, l, id)) {
                continue;
            }
            if self.conns.get(&conn).is_some_and(|c| c.req.timed_sent.contains(&(l, id))) {
                left.commits.insert(b.commit);
                continue;
            }
            let Some((a, due)) = self.keep_at_most_due(&l, b, &id)? else { continue };
            let Some((e, t)) = due else {
                // judged again when its bound or liveness changes (`AtMost`)
                match a {
                    AtMost::Live(t, k) => left.wait_at_most(t, k, b.commit),
                    AtMost::Dead(t, k) => left.wait(t, k, b.commit),
                }
                continue;
            };
            match self.delete_for(keys, &l, &id, &e, Some(WallMs(t)))? {
                Some(item) => {
                    left.commits.insert(b.commit);
                    if let Some(c) = self.conns.get_mut(&conn) {
                        c.req.timed_sent.insert((l, id));
                    }
                    items.push(item);
                }
                None => {
                    left.keyless.insert(b.commit);
                }
            }
        }
        if !items.is_empty() {
            self.command(conn, Command::Delete { label: l, items }, out)?;
        }
        Ok(())
    }

    /// Whether a delta of commit `c` has a live write in this node's state (spec/commits.md §5): a
    /// dropped body keeps its live writes there (spec/crdt.md §4.6); a purged one holds none.
    fn part_live(&mut self, h: &osis_commit::Header, c: &CommitId, p: &(usize, usize)) -> bool {
        let Some(a) = h.aspects.get(p.0) else { return false };
        let o = crate::engine::Owned::of(h, c, p.0);
        if self.engine.core.ix.valueless.get(&(a.tid, a.ak.clone())).is_some_and(|v| o.as_ref().is_some_and(|o| v.contains(o))) {
            return false;
        }
        self.engine.body_live(c, &a.tid, &a.ak).unwrap_or(true)
    }

    /// Whether other entries under the label at the server carry every live write of
    /// must-not-hold entry `e` the label's actor may read (spec/sync.md §7), and the aspects only
    /// a snapshot this node writes can carry.
    /// A kept delta's: a blob of the commit holding it that is not must-not-hold (the dropping
    /// node's rewrite, `carried_by`) or a snapshot covering it; none is asked for while this node
    /// has such a blob placed. A dropped delta's: the snapshot that covered it when it was dropped.
    fn carried(&mut self, at: &At, e: &Entry) -> Result<(bool, Vec<(Tid, Ak)>)> {
        let (g, l, server) = (&at.g, &at.l, at.server.as_ref());
        let Kind::Commit { commit, parts, .. } = &e.kind else { return Ok((false, Vec::new())) };
        let Some(m) = self.engine.core.ix.commits.get(commit).cloned() else { return Ok((false, Vec::new())) };
        let x = self.engine.group_actor(g);
        let (mut all, mut need) = (true, Vec::new());
        for p in parts {
            let Some(a) = m.header.aspects.get(p.0) else { continue };
            let (t, a) = (a.tid, a.ak.clone());
            // a delta the label's actor may not read is carried under its readers' labels
            if !self.engine.core.may_read(&x, &self.engine.core.reader_of(&t)) || !self.part_live(&m.header, commit, p) {
                continue;
            }
            let dropped = m.dropped.contains(p);
            if !dropped && self.carried_by(server, g, l, commit, &[*p]) || self.snapshot_carries(at, commit, &t, &a, dropped)? {
                continue;
            }
            all = false;
            if dropped || !self.carried_by(None, g, l, commit, &[*p]) {
                need.push((t, a));
            }
        }
        Ok((all, need))
    }

    /// Whether a later snapshot of `(t, a)` under the label at the server carries body `body`'s
    /// writes there: one covering it, or for a `dropped` delta (its content is gone, so `covered`
    /// checks only the frontier) the snapshot that covered it when it was dropped, or one
    /// covered-equal to that whose frontier holds the body's counters (a co-writer's that went
    /// up in its place).
    fn snapshot_carries(&mut self, at: &At, body: &CommitId, t: &Tid, a: &Ak, dropped: bool) -> Result<bool> {
        let (l, server, snaps) = (&at.l, at.server.as_ref(), at.snaps);
        let carrier = self.carrier_of(body, t, a);
        let candidates: Vec<CommitId> = match carrier {
            None if dropped => Vec::new(),
            _ => carrier.into_iter().chain(snaps.get(&(*t, a.clone())).cloned().unwrap_or_default()).collect(),
        };
        for s in candidates {
            if s == *body || !self.state.entries_of(l, &s).any(|(b, _)| server.is_none_or(|sv| self.state.is_present(sv, l, &b))) {
                continue;
            }
            let covers = self.engine.covered(&s, body, t, a)? == Some(true);
            let stand_in = match carrier {
                Some(k) => k == s || (covers && self.engine.covered(&s, &k, t, a)? == Some(true) && self.engine.covered(&k, &s, t, a)? == Some(true)),
                None => false,
            };
            if stand_in || (!dropped && covers) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// A right holder that must delete a body with live writes and finds no carrier writes a
    /// covering snapshot first when it may write the aspect (spec/sync.md §7).
    pub(super) fn snapshot_first(&mut self, aspects: &[(Tid, Ak)], body: &CommitId) -> Result<()> {
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

    /// Chunk, tree-node and page blobs among `cands` whose creating deltas this node dropped
    /// (purge, expiry, keep at most, compaction), by the commit and chunk entry that list them,
    /// unless a commit whose creating deltas are not all dropped lists them too (chunk reuse,
    /// spec/sync.md §1). A chunk's creating deltas are those whose delete-key indices are its own
    /// (one class); with no such delta, every delta of the commit. Nor those a live tree links
    /// (spec/sync.md §7: reused chunks and the chunks of compacted values are not in the
    /// linking commit's list): those are returned apart, judged again while trees may link them.
    pub(crate) fn dropped_chunks(&mut self, cands: &BTreeSet<BlobId>) -> Result<(DroppedChunks, BTreeSet<BlobId>)> {
        let mut out = BTreeMap::new();
        if cands.is_empty() {
            return Ok((out, BTreeSet::new()));
        }
        for b in cands {
            let listers: Vec<CommitId> = self.engine.core.ix.by_chunk.get(b).into_iter().flatten().copied().collect();
            let mut first = None;
            let mut live = false;
            for id in listers {
                let Some(m) = self.engine.core.ix.commits.get(&id) else { continue };
                let h = &m.header;
                for ch in h.chunks.iter().filter(|ch| ch.blob == *b) {
                    let class: Vec<usize> = h.aspects.iter().enumerate().filter(|(_, a)| a.keys == ch.keys).map(|(ai, _)| ai).collect();
                    let ais: Vec<usize> = if class.is_empty() { (0..h.aspects.len()).collect() } else { class };
                    let parts = parts_of(h, |i| ais.contains(&i));
                    let dropped = !parts.is_empty() && parts.iter().all(|p| m.dropped.contains(p));
                    if dropped {
                        first.get_or_insert((id, ch.clone()));
                    } else {
                        live = true;
                    }
                }
            }
            if let (false, Some(x)) = (live, first) {
                out.insert(*b, x);
            }
        }
        // the things of the listing commits: reuse and snapshots link within a thing
        let mut by_thing: BTreeMap<Tid, BTreeSet<BlobId>> = BTreeMap::new();
        for (b, (c, _)) in &out {
            for a in self.engine.header(c).map(|h| h.aspects.clone()).unwrap_or_default() {
                by_thing.entry(a.tid).or_default().insert(*b);
            }
        }
        let mut waiting = BTreeSet::new();
        for (t, bs) in by_thing {
            // a tree not all held here may link any of them: its missing nodes are fetched
            // (`tree_wants`) and the chunks judged once they are here
            let linked = self.engine.live_trees(&t)?;
            for b in &bs {
                if !linked.missing.is_empty() || linked.blobs.contains(b) {
                    waiting.insert(*b);
                }
            }
            out.retain(|b, _| !bs.contains(b) || linked.missing.is_empty() && !linked.blobs.contains(b));
            self.tree_wants.extend(linked.missing);
        }
        Ok((out, waiting))
    }

    /// A delete item for a dropped chunk: the label delete key, else a delete key of its delta
    /// (signed for the salt in its prefix; a chunk never fetched is fetched first).
    fn chunk_delete(&mut self, conn: ConnId, keys: &HeadKeys, l: &LabelId, id: &BlobId, (c, ch): &(CommitId, osis_commit::ChunkEntry), out: &mut Vec<super::Action>) -> Result<Option<osis_label::DeleteItem>> {
        if keys.delete.is_some() {
            return Ok(delete_item(keys, l, *id, None, None, &[]));
        }
        let Some(blob) = self.engine.blob(id)? else {
            self.fetch_on(conn, *l, [*id], out)?;
            return Ok(None);
        };
        let Ok(prefix) = osis_label::Prefix::parse(&blob) else { return Ok(None) };
        let dks = self.engine.chunk_delete_secrets(c, ch);
        let Some(hb) = self.engine.header(c).map(|h| h.blind) else { return Ok(None) };
        Ok(delete_item(keys, l, *id, None, Some((prefix.salt(), &hb)), &dks))
    }

    /// A delete item for an entry: the label delete key, else a delete key this node holds.
    fn delete_for(&mut self, keys: &HeadKeys, l: &LabelId, id: &BlobId, e: &Entry, at: Option<WallMs>) -> Result<Option<osis_label::DeleteItem>> {
        if keys.delete.is_some() {
            return Ok(delete_item(keys, l, *id, at, None, &[]));
        }
        Ok(match &e.kind {
            Kind::Commit { commit, parts, salt } => {
                let dks = self.engine.delete_secrets_of(commit, parts);
                let hb = self.engine.header(commit).map(|h| h.blind);
                delete_item(keys, l, *id, at, hb.as_ref().map(|hb| (salt, hb)), &dks)
            }
            _ => None,
        })
    }
}

fn is_membership(a: &Ak) -> bool {
    osis_schema::core_types::is_membership_class(a.as_str())
}
