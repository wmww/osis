//! The pass at one host for one label after its log was read to the end (spec/sync.md §5-§7;
//! spec/permissions.md §4): re-registration first when this admin holds newer epochs than the
//! head (the actor's role commits the host lacks, then the step; the rest after it is
//! registered), then uploads of must-hold bodies (role commits first) or relays of stamped ones,
//! this node's certificates and node card, heartbeats, and deletions of must-not-hold bodies
//! (`delete`: by the label delete key or a delete key, carriers first), timed deletes for
//! relative keep-at-most.

mod delete;

use super::state::{BlobRec, Entry, Kind, HostKey, Touch};
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

/// A node's verdicts on one label at one host (`SyncEngine::verdicts`).
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

/// How long another node's fresh demotion or `keys.0` is left to its author before this node
/// places it as its own chain certificate (ms; the periodic pass picks it up after).
const SETTLE_MS: u64 = 30_000;

/// The least lifetime an inbox blob must have left for its grant to be copied under the home
/// label (`inbox_copies`, spec/sync.md §3): the copy outlives the blob, so a sender's short
/// expiry would free its deposit budget for the next copy at once. At 0 a stranger with the
/// deposit seed stores grants without bound; at `INBOX_LIFETIME` no device ever copies. Past it a
/// device opening a late blob applies the grant without copying: unless another device copied it
/// earlier, the actor's later devices never find it (the device's writes count as acting, so the
/// sender does not re-send). No rule on the blob alone avoids a number: a late genuine blob and a
/// stranger's short-lived one look alike (both expiry and `ts` are the sender's word).
const INBOX_COPY_MIN_LEFT: u64 = osis_base::format::INBOX_LIFETIME_MS / 2;

/// The least a writer waits, after receiving another node's commit or seeing a deposit, before
/// it uploads or promotes it itself (ms); the most is `SETTLE_MS`. The point in between is this
/// node's per blob (`relay_due`), so the author or the first co-writer is usually done and the
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
type Desired = BTreeMap<CommitId, Vec<Vec<(usize, usize)>>>;

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
type Deposit = (BlobId, Entry, CommitId, Vec<(usize, usize)>);

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
        let host = c.host;
        let Some(lc) = c.labels.get(&l).filter(|x| !x.receipts) else { return Ok(()) };
        let (g, index) = (lc.group, lc.index);
        let Some(head) = lc.head.clone() else { return Ok(()) };
        // secrets may have arrived since the head was accepted
        self.recheck_doubts();
        let (keys, read_ok) = self.usable_keys(&g, index, &head)?;
        if let Some(lc) = self.lc_mut(conn, &l) {
            lc.keys = keys.clone();
        }
        // certificate copies that waited for the rotation just run
        if read_ok {
            let (now, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.deferred).into_iter().partition(|x| x.0 == g);
            self.deferred = later;
            let owed: BTreeSet<[u8; 32]> = now.iter().filter_map(|x| x.3).collect();
            for (x, c, ais, k) in now {
                self.place_certificate_in(&x, &c, &ais, k)?;
            }
            for k in owed {
                self.settle_owed(k);
            }
        }
        // a complete pass and still no secret of the head's read epoch: stranded
        if keys.epochs[0].is_none() {
            return self.stranded(conn, g, l, out);
        }
        if self.reregister(conn, l, out)? {
            return Ok(());
        }
        let p = Head { g, l, host: Some(host), id: head.id(), keys, read_ok };
        self.with_work(&g, Some(conn), l, |s, ctx, w| s.judge_label(conn, &p, ctx, w, out))
    }

    /// Runs a pass of `l` of `g` over its work set (`conn` `None`: the local pass): the closure
    /// synced and the engine's changes spread first; what touches the set during the pass
    /// collects in its place and joins it after; a failed pass judges everything next time.
    fn with_work(&mut self, g: &Tid, conn: Option<ConnId>, l: LabelId, f: impl FnOnce(&mut Self, &BodyCtx, &mut Work) -> Result<()>) -> Result<()> {
        // atomic apply waits for the deltas of this group's closure (spec/commits.md §4)
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

    /// The pass after the keys and registration (`pass`): over what work set `w` names, or
    /// everything when it says so or an input of the pass changed (`work`).
    fn judge_label(&mut self, conn: ConnId, p: &Head, ctx: &BodyCtx, w: &mut Work, out: &mut Vec<super::Action>) -> Result<()> {
        let (g, l, keys, read_ok) = (p.g, p.l, &p.keys, p.read_ok);
        let Some(host) = p.host else { return Ok(()) };
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
        let mut sends: Vec<Out> = self.body_sends(p, &bodies, &snaps, &snapping, &mut left)?;
        // parked commits travel like at a host: stamped entries are relayed (spec/versioning.md §2)
        for id in self.state.of_kind(&l, 4) {
            if self.state.entries.get(&(l, id)).is_some_and(|e| e.stamp.is_some()) {
                sends.push(Out { prio: 3, id, fresh: false, of: None });
            }
        }
        if !replaced && (keys.is_writer() || keys.deposit.is_some()) {
            if read_ok {
                self.inbox_copies(&g, l)?;
                let authors: BTreeSet<Tid> = w.unjudged.values().copied().collect();
                self.certificates(&g, l, false, &authors)?;
                let tight = self.lc(conn, &l).and_then(|x| x.budget).is_some_and(|b| b < self.cfg.tight_budget);
                self.heartbeat(&g, l, keys, tight, &ctx.closure)?;
            } else if !self.may_rotate_read(&g) {
                // the revokes of departures inside holders and their chains' keysets only: they
                // tell the label's rotators what keeps its epoch uncovered and what to seal to
                // (spec/permissions.md §4 exception)
                self.certificates(&g, l, true, &BTreeSet::new())?;
            }
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
        self.send(conn, p, sends, &mut left, out)?;
        let settled = unsettled.is_empty();
        self.pull(Some(conn), &g, l, &mut scope, w);
        self.judge_touched(ctx, &g, &l, &scope, &judged, &mut bodies)?;
        self.deletions(conn, &p.at(&snaps, settled), &bodies, &scope, &mut left, out)?;
        if quiet && settled {
            self.retire_at(host, &g, l)?;
        }
        self.reseal(&g, w)?;
        self.repair_suspects(w)?;
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
            let beat = c.and_then(|c| self.engine.header(&c)).is_some_and(|h| h.aspects.iter().any(|a| a.ak.as_str() == "seen.0"));
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

    /// Sends what a pass at `conn`'s host found to send, by priority: what the host lacks
    /// and is not in flight, stamped when this node writes (promoting due deposits too), else
    /// relayed with its stamp, else deposited (this node's own role writes queued in the
    /// outbox). What the host lacks is judged again next pass (`left`).
    fn send(&mut self, conn: ConnId, p: &Head, mut sends: Vec<Out>, left: &mut Left, out: &mut Vec<super::Action>) -> Result<()> {
        let (g, l, keys) = (p.g, p.l, &p.keys);
        let Some(host) = p.host else { return Ok(()) };
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
                    None => false,
                };
            }
            if !seen.insert(o.id) || settled || self.conns.get(&conn).is_some_and(|c| super::in_flight(c, &c.req.sent, (l, o.id), raw) || c.req.replacing.contains_key(&(l, o.id))) {
                continue;
            }
            let Some(e) = self.state.entries.get(&(l, o.id)).cloned() else { continue };
            let Some(blob) = self.engine.blob(&o.id)? else { continue };
            if let Some(w) = &keys.write {
                let stamp = osis_label::sign_stamp(w, &l, &o.id, &e.wrap);
                uploads.push(osis_proto::Entry { blob, wrap: e.wrap, stamp, replaces: Vec::new() });
                // kept, so a later pass does not promote it again
                let mut e = e;
                e.stamp = Some(stamp);
                self.state.set_entry(l, o.id, e);
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
        }
        if let Some(c) = self.conns.get_mut(&conn) {
            c.req.sent.extend(uploads.iter().map(|u| osis_label::blob_id(&u.blob)).chain(deposits.iter().map(|d| osis_label::blob_id(&d.0))).map(|b| ((l, b), (raw, super::UNTAGGED))));
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
        let snaps = self.drop_label_covered(&entries, &mut scope, !unsettled.contains(&None), &mut left)?;
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
                commits.extend(self.engine.core.durable_on(&(*t, a.clone())));
            }
        }
        if full {
            self.stats.full += 1;
        }
        full
    }

    /// Local passes over the labels this node syncs with nobody (no host in their `label.0`):
    /// this node is their host, so a peer that dials it (a direct link's redeemer,
    /// spec/permissions.md §9) finds a complete state (spec/sync.md §5, co-reader peer). Passes
    /// otherwise run only per dialed connection, and a node serves only the entries they placed.
    pub(crate) fn local_passes(&mut self) -> Result<()> {
        self.local_dirty = false;
        self.local_last = self.raw_now();
        // nobody can dial a node without `reach.0` (no listener): nothing to serve
        if self.own_reach().is_none() {
            self.local_any = false;
            return Ok(());
        }
        let labels: Vec<(Tid, LabelId, u64)> = self.labels().into_iter().filter(|(_, l)| !l.replaced && super::peers::hostless(&l.hosts)).map(|(g, l)| (g, l.id, l.index)).collect();
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
    /// of the actor (a `secrets.0` write) received less than `SETTLE_MS` ago is its author's to
    /// register first (a second admin's step, issued before the author's reaches it, would be a
    /// sibling); a wake brings the pass back then. Other role writes (an admin recording
    /// a step in `label.0`, a `keys.0` update) get no step from their author and delay nothing.
    fn step_settled(&mut self, g: &Tid) -> bool {
        let a = self.engine.core.secret_actor(g).unwrap_or(*g);
        let Some(t) = self.rotation_at.get(&a).map(|t| t.saturating_add(SETTLE_MS)) else { return true };
        if t <= self.raw_now() {
            return true;
        }
        self.settle_by(t);
        false
    }

    /// One label's local pass, as a pass at a host would leave that host: a newer
    /// established epoch first issues a child step of the head when that head is recorded in
    /// `label.0` (recorded there, so the served head moves; `reregister` without the upload),
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
        // the label's work set, as at a host (`judge_label`)
        let p = Head { g, l, host: None, id: head.id(), keys, read_ok };
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
        self.heartbeat(&g, l, keys, false, &ctx.closure)?;
        if let Some(wk) = &keys.write {
            self.local_promote(&g, l, wk, &scope, &ours, &mut left)?;
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
        // a node serving the label alone decides here: nobody runs a pass at a host for it
        self.reseal(&g, w)?;
        self.repair_suspects(w)?;
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
    pub(super) fn drop_label_covered(&mut self, entries: &BTreeMap<(Tid, Ak), BTreeSet<(BlobId, CommitId)>>, scope: &mut Scope, opened: bool, left: &mut Left) -> Result<Snaps> {
        let snaps: BTreeMap<(Tid, Ak), Vec<CommitId>> = entries.iter().map(|(k, v)| (k.clone(), v.iter().map(|(_, c)| *c).collect())).collect();
        // what goes without a right (spec/permissions.md §8), once every entry is open: what a
        // setting broke may stand again with a role commit still to come (judged again when
        // settled, `deletions`)
        let only = match &*scope {
            Scope::All => None,
            Scope::Some { commits, .. } => Some(commits),
        };
        let mut dropped: BTreeSet<CommitId> = if opened { self.engine.drop_broken(only)?.into_iter().collect() } else { BTreeSet::new() };
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
    /// each body (at `host` if there, else any genuine one; `None`: this node's own served
    /// state, any entry), else a fresh placement when this node may upload or deposit it, with
    /// the blobs it links when this node writes. Another node's body not at `host` waits for
    /// its author or a co-writer (`relay_due`).
    fn body_sends(&mut self, p: &Head, bodies: &[Body], snaps: &Snaps, snapping: &Unsettled, left: &mut Left) -> Result<Vec<Out>> {
        let (g, l, keys, read_ok, host) = (&p.g, p.l, &p.keys, p.read_ok, p.host.as_ref());
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
            let entry = self.entry_for(host, &l, b);
            // another blob of the commit holding every needed delta holds it (a projection a
            // right holder dropped covered deltas from, a superset), unless it is must-not-hold
            // (`holds_nothing`, spec/sync.md §6)
            let here = entry.is_some_and(|id| host.is_none_or(|s| self.state.is_present(s, &l, &id)));
            if !here && self.carried_by(host, g, &l, &b.commit, &needed) {
                continue;
            }
            // a right holder deleted it here: its keep bounds, dated by its own deaths, passed
            // there (spec/commits.md §5); not placed again while its live writes are carried
            if !here && self.state.body_deleted(l, b.commit, &b.parts) && self.live_carried(b, &needed, snaps, &mut note)? {
                continue;
            }
            // another node's commit not at this host: its author (or a co-writer) first
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
            } else if b.role_commit {
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
    /// holds, established, the head's epochs (`keys`) and a newer one, or the head's deposit key
    /// is not the one the actor's deposit seed derives (refreshed) and nothing under `l` that
    /// could carry a newer seed waits to be opened or applied (`keys_caught_up`: else a lagging
    /// admin would register its older seed back); a replaced label never.
    fn step_due(&mut self, g: &Tid, l: &LabelId, keys: &HeadKeys) -> bool {
        if keys.delete.is_none() || keys.write.is_none() || self.is_replaced(g, l) {
            return false;
        }
        if self.engine.epochs(g).is_some_and(|e| osis_keys::newer_than_head(&e, keys.epochs)) {
            return true;
        }
        keys.deposit.is_none() && self.engine.deposit_seed(g).is_ok_and(|s| s.is_some()) && self.keys_caught_up(g, l)
    }

    /// No entry under `l` this node can open, present at a host it is connected to that has
    /// not said it lacks it, is unopened (in flight, or not fetched), and no pending commit by an
    /// admin writes the actor's `keys.0` (`Engine::keys_write_pending`). Entries only a host out
    /// of reach lists do not count: one that never comes back would hold the step back for good.
    fn keys_caught_up(&mut self, g: &Tid, l: &LabelId) -> bool {
        let secrets = self.read_secrets(g);
        let fetchable: BTreeSet<BlobId> = self.conns.values().filter(|c| c.up).flat_map(|c| self.state.present_at(&c.host, l).into_iter().filter(|b| !c.req.missing.contains(b))).collect();
        let unopened = fetchable.into_iter().any(|b| {
            self.state.entries.get(&(*l, b)).is_some_and(|e| e.kind == Kind::Unknown && (e.shredded() || osis_label::unwrap_any(secrets.iter(), &b, &e.wrap).is_some()))
        });
        if unopened {
            return false;
        }
        let a = self.engine.core.secret_actor(g).unwrap_or(*g);
        !self.engine.keys_write_pending(&a).unwrap_or(true)
    }

    /// Repair (spec/sync.md §7): for each aspect another node's newest heartbeat under the label
    /// reports suspect (`Work::beats`), of a thing in the label this node may write, whose
    /// state digest here differs from the reported one: a snapshot of it from this node's whole
    /// state, an ordinary compaction snapshot (it joins with the others', never resurrects
    /// expired or purged values). Once per reported entry (heartbeat commit, aspect): each node
    /// beats at most once per `HEARTBEAT_MIN_INTERVAL` per label. Every entry acted on is a
    /// diagnostic, so silent repairs hide nothing.
    fn repair_suspects(&mut self, w: &Work) -> Result<()> {
        let beats: Vec<(Tid, CommitId)> = w.beats.iter().filter_map(|(n, s)| s.iter().next_back().map(|(_, c)| (*n, *c))).collect();
        let seen_ak = Ak::new("seen.0").map_err(|_| crate::Error::Misuse("ak"))?;
        for (node, c) in beats {
            let Some(v) = self.engine.part_value(&c, &node, &seen_ak)? else { continue };
            let Ok(seen) = <ct::Seen as osis_schema::Codec>::from_value(&v) else { continue };
            for s in seen.suspect {
                let Ok(ak) = Ak::new(&s.ak) else { continue };
                if !w.closure.contains(&s.thing) || ct::is_role_class(ak.as_str()) || ak.as_str() == "created.0" || !self.repaired.insert((c, s.thing, ak.clone())) {
                    continue;
                }
                if self.engine.role_on(&s.thing) < Some(Role::Write) {
                    continue;
                }
                let mine = self.engine.state_digest(&s.thing, &ak)?;
                if mine.is_none() || mine == Some(s.digest) {
                    self.repair_diag(node, s.thing, None, format!("suspect {} {} reported by {node}: same state here", s.thing, s.ak));
                    continue;
                }
                match self.engine.snapshot(&s.thing, &ak) {
                    Ok(snap) => self.repair_diag(node, s.thing, snap, format!("suspect {} {} reported by {node}: re-snapshotted", s.thing, s.ak)),
                    Err(e) => self.diag(format!("repair of {} {}: {e}", s.thing, s.ak)),
                }
            }
        }
        Ok(())
    }

    fn repair_diag(&mut self, node: Tid, thing: Tid, commit: Option<CommitId>, detail: String) {
        let now = self.engine.now();
        self.engine.core.events.diagnostic(crate::events::Diagnostic { kind: crate::events::DiagnosticKind::Repair, tids: vec![node, thing], commit, peer: Some(node), detail }, now);
    }

    /// Re-seals decided at the end of a complete pass of the actor's labels (spec/permissions.md
    /// §3): holders seen without a box at a current epoch (`Engine::reseal_due`) and holders
    /// whose node's heartbeat under the label reports it stranded (§4); delivered by inbox and
    /// placed under the actor's labels like any role commit.
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
        // plain things under `a` with holders: secrets of their own again
        for (t, r) in self.engine.own_secrets_due(&a, &Passed)? {
            match r {
                Ok(done) => self.take_done(done)?,
                Err(e) => self.diag(format!("secrets of its own for {t}: {e}")),
            }
        }
        // the newest heartbeat of each node under the label, when it reports it stranded
        // (`Work::beats`); before the boxes `reseal_due` adds, which would box a stranded holder
        // lacking one twice
        let beats: Vec<(Tid, CommitId)> = w.beats.iter().filter_map(|(n, s)| s.iter().next_back().map(|(_, c)| (*n, *c))).collect();
        for (node, c) in beats {
            if self.resealed.contains(&c) || !self.engine.get_typed(&node, &ct::SEEN)?.is_some_and(|s| s.stranded) {
                continue;
            }
            self.resealed.insert(c);
            // the holder of the actor the node reads through: itself or up its owner chain
            let holders: BTreeSet<Tid> = self.engine.core.current_holders(&a).into_iter().map(|x| x.0).collect();
            // a node that may not re-seal that holder leaves it to one that may
            let holder = self.engine.owner_chain(&node).find(|t| holders.contains(t));
            if let Some(t) = holder
                && let Ok(done) = self.engine.reshare(&a, &t)
            {
                self.take_done(done)?;
            }
        }
        match self.engine.reseal_due(&a, &Passed) {
            Ok(done) => self.take_done(done)?,
            Err(e) => self.diag(format!("re-seal of {a}: {e}")),
        }
        Ok(())
    }

    /// This node's verdicts on label `l` at `host` under the keys its last pass there used
    /// (simulator invariants, spec/sync.md §6); `None` when the label is not open there.
    pub fn verdicts(&mut self, host: &HostKey, l: &LabelId) -> Result<Option<Verdicts>> {
        let Some(lc) = self.conns.values().filter(|c| c.host == *host).find_map(|c| c.labels.get(l).filter(|x| x.phase == super::Phase::Open)) else { return Ok(None) };
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
                // not placed again (`body_sends`)
                if self.state.body_deleted(*l, b.commit, &b.parts) && self.live_carried(b, &needed, &snaps, &mut note)? {
                    continue;
                }
                v.must_hold.push((b.commit, needed));
            }
        }
        let desired = desired(&bodies);
        let entries: Vec<(BlobId, Entry)> = self.state.label_entries(l).map(|(b, e)| (b, e.clone())).collect();
        let at = At { g, l: *l, host: Some(*host), keys: &keys, snaps: &snaps, settled: unsettled.is_empty() };
        for (id, e) in entries {
            if let Fate::Delete(why, _, _) = self.deletable(&at, &id, &e, &desired, false, &mut note)? {
                v.must_not.push((id, format!("{why:?}")));
            }
        }
        Ok(Some(v))
    }

    /// The bodies label `l` of `g` should hold: the closure's; under a replaced label
    /// role-class ones only (spec/sync.md §2: its content entries go).
    pub(super) fn bodies_under(&mut self, g: &Tid, l: &LabelId) -> Result<Vec<Body>> {
        let mut bodies = self.engine.label_bodies_meta(g)?;
        if self.is_replaced(g, l) {
            bodies.retain(|b| b.role_commit);
        }
        Ok(bodies)
    }

    pub(crate) fn is_replaced(&mut self, g: &Tid, l: &LabelId) -> bool {
        self.engine.labels_of(g).iter().any(|x| x.id == *l && x.replaced)
    }

    /// Entries present at `host` that unwrap under a held read secret and were never opened:
    /// opened now, or fetched again when their bytes are not here (a fetch lost to a cut or
    /// crash, secrets that arrived later).
    fn refetch(&mut self, conn: ConnId, host: HostKey, l: LabelId, w: &Work, out: &mut Vec<super::Action>) -> Result<()> {
        let missing = |s: &Self, b: &BlobId| s.conns.get(&conn).is_some_and(|c| c.req.missing.contains(b));
        let ids: Vec<BlobId> = w.unopened.iter().filter(|b| !self.fetching(b) && !missing(self, b) && self.state.is_present(&host, &l, b)).copied().collect();
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
                (Ok(p), Ok((expiry, keys))) => parts.is_empty() || p.agrees(expiry.map(WallMs), &h.blind, &keys, osis_label::Class::Durable),
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
    /// entries that do not open as a commit or whose bytes no host delivers.
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

    /// Deposited commit entries at `host` a writer may promote now: past this node's wait
    /// (`RELAY_MIN_MS`: a co-writer may promote it first), not in flight, never a heartbeat.
    fn due_deposits(&mut self, conn: ConnId, host: HostKey, l: LabelId) -> Vec<Deposit> {
        let ids: Vec<(BlobId, Entry)> = self.state.deposited_at(&host, &l).into_iter().filter_map(|b| self.state.entries.get(&(l, b)).map(|e| (b, e.clone()))).collect();
        let raw = self.raw_now();
        self.deposit_seen.retain(|k, _| self.state.deposited.contains(k));
        let mut out = Vec::new();
        for (id, e) in ids {
            if self.conns.get(&conn).is_some_and(|c| super::in_flight(c, &c.req.sent, (l, id), raw)) {
                continue;
            }
            let seen = *self.deposit_seen.entry((host, l, id)).or_insert(raw);
            let due = seen.saturating_add(self.relay_delay(&id.0));
            if raw < due {
                self.settle_by(due);
                continue;
            }
            let Kind::Commit { commit, parts, .. } = &e.kind else { continue };
            let Some(h) = self.engine.header(commit) else { continue };
            if h.aspects.iter().any(|a| a.ak.as_str() == "seen.0") {
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
    fn complete_chains(&mut self, conn: ConnId, host: HostKey, g: &Tid, l: LabelId) -> Result<()> {
        for (_, _, c, parts) in self.due_deposits(conn, host, l) {
            self.complete_chain(Some(host), g, l, &c, &parts)?;
        }
        Ok(())
    }

    /// Places the parts of the author's chain for `parts` of `c` that no entry under `l` holds
    /// at `host` (`chain_missing`) as this node's certificate copies, when it holds them all.
    /// Returns whether the chain is complete under `l` now (`None` host: this node's served
    /// state, where a copy is in place once placed); `None` for a commit not applied here.
    fn complete_chain(&mut self, host: Option<HostKey>, g: &Tid, l: LabelId, c: &CommitId, parts: &[(usize, usize)]) -> Result<Option<bool>> {
        let Some(missing) = self.chain_missing(host, g, l, c, parts)? else { return Ok(None) };
        if missing.is_empty() {
            return Ok(Some(true));
        }
        let mut bodies = Vec::new();
        for (x, p) in &missing {
            let bs = self.engine.part_bodies(x, p)?;
            let got: BTreeSet<(usize, usize)> = bs.iter().flat_map(|b| b.parts.iter().copied()).collect();
            if !p.is_subset(&got) {
                return Ok(Some(false));
            }
            bodies.push((*x, p.clone(), bs));
        }
        for (x, p, bs) in bodies {
            for b in bs {
                self.place(g, l, &b, true)?;
            }
            self.place_linked(l, &x, &p)?;
            self.state.add_cert(l, x);
        }
        Ok(Some(host.is_none()))
    }

    /// A writer serving `l` with no host promotes the deposits there as at a host
    /// (`complete_chains`, `promote`; spec/sync.md §5): another node's deposited commit it
    /// applied, past the relay wait since it arrived (a co-writer or the author may place the
    /// chain first), never a heartbeat, gets the missing parts of its author's chain placed as
    /// this node's certificate copies, then its stamp; one whose chain it cannot complete
    /// stays a deposit and is judged again next pass (one not applied yet, once applied). Of
    /// the entries `scope` names, but `ours` (this pass's placements).
    fn local_promote(&mut self, g: &Tid, l: LabelId, write: &osis_crypto::SigningSecret, scope: &Scope, ours: &BTreeSet<BlobId>, left: &mut Left) -> Result<()> {
        for id in self.scope_entries(&l, scope).difference(ours).copied().collect::<Vec<_>>() {
            let Some(mut e) = self.state.entries.get(&(l, id)).cloned() else { continue };
            let Kind::Commit { commit, parts, .. } = &e.kind else { continue };
            let (commit, parts) = (*commit, parts.clone());
            if e.stamp.is_some() || e.cert || self.own(&commit) || self.engine.header(&commit).is_none_or(|h| h.aspects.iter().any(|a| a.ak.as_str() == "seen.0")) {
                continue;
            }
            if let Some(t) = self.relay_at(&commit) {
                left.at(t, commit);
                continue;
            }
            match self.complete_chain(None, g, l, &commit, &parts)? {
                Some(true) => {}
                Some(false) => {
                    left.commits.insert(commit);
                    continue;
                }
                None => continue,
            }
            e.stamp = Some(osis_label::sign_stamp(write, &l, &id, &e.wrap));
            self.state.set_entry(l, id, e);
        }
        Ok(())
    }

    /// A writer re-uploads stamped the deposited entries it verified (spec/sync.md §5): applied
    /// commits whose author's chain is under the label (`complete_chains` placed what it held
    /// of it), never a heartbeat; per host (a blob may be deposited at several).
    fn promote(&mut self, conn: ConnId, host: HostKey, g: &Tid, l: LabelId, write: &osis_crypto::SigningSecret, uploads: &mut Vec<osis_proto::Entry>) -> Result<()> {
        for (id, mut e, c, parts) in self.due_deposits(conn, host, l) {
            if uploads.iter().any(|u| osis_label::blob_id(&u.blob) == id) || !self.chain_missing(Some(host), g, l, &c, &parts)?.is_some_and(|m| m.is_empty()) {
                continue;
            }
            let Some(blob) = self.engine.blob(&id)? else { continue };
            let stamp = osis_label::sign_stamp(write, &l, &id, &e.wrap);
            uploads.push(osis_proto::Entry { blob, wrap: e.wrap, stamp, replaces: Vec::new() });
            e.stamp = Some(stamp);
            self.state.set_entry(l, id, e);
            // still deposited there until the host takes the stamped upload (a refusal, say a
            // step registered meanwhile, leaves it for the next pass)
        }
        Ok(())
    }

    /// The parts of the author's chain for `parts` of commit `c` (`Engine::author_chain`) that
    /// no entry under `l` holds at `host` (`held_parts_at`: the promotion or deletion is
    /// that host's; `None`: this node's served state); `None` when this node has not applied
    /// `c`.
    fn chain_missing(&mut self, host: Option<HostKey>, g: &Tid, l: LabelId, c: &CommitId, parts: &[(usize, usize)]) -> Result<Option<BTreeMap<CommitId, Parts>>> {
        let Some(chain) = self.engine.author_chain(c, &parts.iter().copied().collect()) else { return Ok(None) };
        let closure = self.engine.closure(g);
        let mut out = BTreeMap::new();
        for (x, want) in chain {
            let (_, held) = self.held_parts_at(g, l, &x, host.as_ref().map(std::slice::from_ref))?;
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

    /// Whether this node uploads or relays commit `c` at a host lacking it now: its own (made
    /// here, a held key actor's included, or placed first by a flow) at once, another node's once `relay_delay` has passed since it
    /// arrived here (else a wake is set for then).
    fn relay_due(&mut self, c: &CommitId) -> bool {
        self.relay_at(c).is_none()
    }

    /// `relay_due` as the time (corrected wall ms) it comes, `None` once due.
    fn relay_at(&mut self, c: &CommitId) -> Option<u64> {
        let me = self.engine.tid();
        let m = self.engine.core.ix.commits.get(c)?;
        if m.origin == crate::events::Origin::Local || m.header.author == me || self.first.contains(c) {
            return None;
        }
        let due = m.received.0.saturating_add(self.relay_delay(&c.0));
        let now = self.now();
        if now >= due {
            return None;
        }
        let at = self.raw_now().saturating_add(due - now);
        self.settle_by(at);
        Some(due)
    }

    /// Whether this node placed the entry (its certificates, heartbeats, role writes).
    fn mine(&self, e: &Entry) -> bool {
        e.cert || matches!(&e.kind, Kind::Commit { commit, .. } if self.own(commit))
    }

    /// A non-writer deposits its own role writes (an invite grant, a self-removal,
    /// spec/sync.md §3).
    fn may_deposit(&self, keys: &HeadKeys, b: &Body) -> bool {
        keys.deposit.is_some() && b.role_commit && self.own(&b.commit)
    }

    /// Must-hold for a closure body (spec/sync.md §6): before its keep-at-least bound, under
    /// `nobody` while kept, or established uncovered by the label's snapshots. Must-hold: the parts a blob of the commit
    /// must hold to hold the body (all of them before keep-at-least or under `nobody`, else those of the aspects
    /// no snapshot covers).
    fn must_hold(&mut self, b: &Body, snaps: &Snaps, unsettled: &Unsettled, note: &mut Note) -> Result<Option<Vec<(usize, usize)>>> {
        let Some(h) = self.engine.header(&b.commit) else { return Ok(None) };
        let aspects: Vec<(Tid, Ak)> = b.parts.iter().filter_map(|(ai, _)| h.aspects.get(*ai)).map(|a| (a.tid, a.ak.clone())).collect();
        let now = self.now();
        let mut before = false;
        if let Some((t, a)) = aspects.first() {
            let at_least = self.engine.body_keep(&b.commit, t, a)?.at_least;
            // no right holder will ever drop a `nobody` body: must-hold while kept, covered or not
            let nobody = b.parts.first().and_then(|(ai, _)| h.aspects.get(*ai)).is_some_and(|x| x.retention.by == osis_base::PurgeBy::Nobody);
            before = nobody || at_least > now;
            if at_least > now {
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

    /// Whether each of `parts` of body `b` has no live write or a snapshot under the label
    /// (`snaps`) covering it.
    fn live_carried(&mut self, b: &Body, parts: &[(usize, usize)], snaps: &Snaps, note: &mut Note) -> Result<bool> {
        let Some(h) = self.engine.header(&b.commit) else { return Ok(false) };
        for p in parts {
            if self.part_live(&h, &b.commit, p) && !self.parts_covered(snaps, &b.commit, &h, &[*p], note)? {
                return Ok(false);
            }
        }
        Ok(true)
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

    /// Whether an entry of commit `c` holding `parts` is present at `host` under `l` (any
    /// entry when `None`: this node's own served state), checked genuine: a forged blob listing
    /// the parts holds nothing, nor a must-not-hold one (`holds_nothing`).
    fn carried_by(&mut self, host: Option<&HostKey>, g: &Tid, l: &LabelId, c: &CommitId, parts: &[(usize, usize)]) -> bool {
        let ids: Vec<BlobId> = self.state.entries_of(l, c).filter(|(id, e)| !e.cert && matches!(&e.kind, Kind::Commit { parts: p, .. } if parts.iter().all(|x| p.contains(x)) && !self.holds_nothing(g, c, p)) && host.is_none_or(|s| self.state.holds_at(s, l, id))).map(|(id, _)| id).collect();
        ids.into_iter().any(|id| self.genuine(&id))
    }

    /// Whether a blob of commit `c` with delta set `parts` under a label of `g` is must-not-hold
    /// whatever its siblings: it holds a delta this node dropped (purge, expiry, keep-at-most,
    /// compaction) or one the label's actor may not read (outside the required set). It holds
    /// no body and makes no other blob a strict subset (spec/sync.md §6).
    fn holds_nothing(&self, g: &Tid, c: &CommitId, parts: &[(usize, usize)]) -> bool {
        let Some(m) = self.engine.core.ix.commits.get(c) else { return false };
        let x = self.engine.group_actor(g);
        parts.iter().any(|p| m.dropped.contains_key(&p.0) || m.header.aspects.get(p.0).is_some_and(|a| !self.engine.core.may_read(&x, &self.engine.core.reader_of(&a.tid))))
    }

    /// The genuine entry under `l` holding exactly this body, not tombstoned at `host`, whoever
    /// placed it (a certificate copy of the same parts holds it too: other nodes see one entry).
    /// One present at `host` first: the label then holds the body (spec/sync.md §6), and
    /// uploading another encryption (this node's own, whose upload was lost) would only add a
    /// duplicate for the tiebreak of §7 to delete. `None`: any entry (this node's served state).
    fn entry_for(&mut self, host: Option<&HostKey>, l: &LabelId, b: &Body) -> Option<BlobId> {
        let mut ids: Vec<BlobId> = self.state.entries_of(l, &b.commit).filter(|(id, e)| matches!(&e.kind, Kind::Commit { parts, .. } if *parts == b.parts) && host.is_none_or(|s| !self.state.is_gone_at(s, l, id))).map(|(id, _)| id).collect();
        if let Some(host) = host {
            ids.sort_by_key(|id| !self.state.is_present(host, l, id));
        }
        ids.into_iter().find(|id| self.genuine(id))
    }

    /// Whether every delta of commit blob `id` hashes to its header entry (spec/commits.md §4;
    /// `Engine::parts_genuine`). Opening a blob checks its prefix, not its deltas, and a held
    /// commit's late parts are skipped unchecked, so an entry's parts are only its own claim
    /// until this says yes. A forged blob is marked `Bad` under every label; unknown yet (a
    /// thing's `created.0` missing) counts as no.
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

    /// A grantee device places a certificate copy of what `g`'s inbox brought, once applied,
    /// under `g`'s home label `l` (spec/sync.md §3; the inbox may be another label, its owner's:
    /// a group's holders learn its edges there, its inbox reaching only its admins): of a
    /// role commit, the carried parts on the things it writes an edge of `g` or an actor
    /// it owns on, or boxes one on (boxes are sealed to the actor anyway), with the `label.0` and
    /// `created.0` commits of those things, so the actor's other devices find the grant and its
    /// labels there; nothing from a blob expiring less than `INBOX_COPY_MIN_LEFT` from now (an expiry
    /// is the sender's word: a short one would free the deposit budget for the next copy), and
    /// not what an entry there already holds (each holder of a group actor reads its inbox and
    /// placed the same copy again). The consumed inbox blob stays until it expires: its label
    /// hints are what a later holder that cannot apply the copied `label.0` yet (the granter's
    /// chain pending) opens the thing's label by.
    fn inbox_copies(&mut self, g: &Tid, l: LabelId) -> Result<()> {
        // only under the actor's home label (spec/sync.md §3): an inbox at another group's label
        // would show that group's readers the actor's edges, labels and box keys
        if self.engine.core.secret_actor(g) != Some(*g) {
            return Ok(());
        }
        let Some(li) = self.inbox_label(g) else { return Ok(()) };
        let now = self.now();
        let opened: Vec<(BlobId, CommitId)> = self.state.label_entries(&li).filter_map(|(b, e)| if let Kind::Inbox(Some(c)) = e.kind { Some((b, c)) } else { None }).collect();
        for (b, c) in opened {
            if self.state.certs.contains(&(l, c)) || self.engine.core.ix.pending.contains_key(&c) {
                continue;
            }
            let Some(m) = self.engine.core.ix.commits.get(&c).cloned() else { continue };
            let Some(o) = self.inbox_opened(&li, &b)? else { continue };
            if o.until < now.saturating_add(INBOX_COPY_MIN_LEFT) {
                continue;
            }
            // a valid commit only
            if !o.ais.iter().all(|ai| m.valid.get(*ai).copied().unwrap_or(false)) {
                continue;
            }
            // the carried parts on the things the commit has an edge or box of the actor on (the
            // payload carries the sender's choice of parts; a role commit's are all
            // role-class)
            let named = self.engine.holders_named(&c);
            let on: BTreeSet<Tid> = named.iter().filter(|(_, ms)| ms.iter().any(|x| self.engine.owner_chain(x).any(|y| y == *g))).filter_map(|(ai, _)| m.header.aspects.get(*ai).map(|a| a.tid)).collect();
            let ais: BTreeSet<usize> = o.ais.iter().copied().filter(|ai| m.header.aspects.get(*ai).is_some_and(|a| on.contains(&a.tid))).collect();
            if ais.is_empty() {
                continue;
            }
            // another holder's copy is there: done, as if placed here
            if self.held_whole(g, l, &c, &ais)? {
                self.state.add_cert(l, c);
                continue;
            }
            // labels only of those things the payload names (its list is the sender's word: it
            // could name any thing this device holds)
            for t in o.things.iter().map(|t| t.tid).filter(|t| on.contains(t)) {
                for ak in ["created.0", "label.0"] {
                    let Some((x, xs)) = self.engine.aspect_commit(&t, ak) else { continue };
                    if !self.state.certs.contains(&(l, x)) && !self.held_whole(g, l, &x, &xs)? {
                        self.place_certificate_in(g, &x, &xs, None)?;
                    }
                }
            }
            self.place_certificate_in(g, &c, &ais, None)?;
        }
        Ok(())
    }

    /// This node's chain certificates and node card under `l` (spec/permissions.md §4): the
    /// aspects no entry under the label holds yet, as a fresh encryption per label. Another
    /// node's entry counts only when this node checked it genuine (`genuine`), it is present at
    /// every host this node syncs the label with (the decision is the label's, not one
    /// host's), and a newcomer can open it: one granted after a rotation gets the history
    /// boxes with its grant (spec/crypto.md §4) and opens entries under older epochs like the
    /// label's older content, except a rotation commit of the label's actor, which is wrapped
    /// under the epoch it supersedes (spec/crypto.md §5): such an entry counts only when it
    /// opens under the newest read secret.
    fn certificates(&mut self, g: &Tid, l: LabelId, revokes_only: bool, authors: &BTreeSet<Tid>) -> Result<()> {
        let closure = self.engine.closure(g);
        let mut own_removals = BTreeSet::new();
        let wanted = if revokes_only {
            // under an epoch a departure inside a holder leaves uncovered: those revokes and keysets only
            let actor = self.engine.group_actor(g);
            self.engine.inside_holder_revokes(&actor, &closure)
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
            // removals of the label's actor's edges on things in its closure, whoever made them
            // (spec/permissions.md §2): its holders still holding such an edge would re-upload
            // the thing's bodies that others delete, on every pass
            let actor = self.engine.group_actor(g);
            let (removals, own) = self.engine.removal_certificates(&actor, &closure);
            for (c, p) in removals {
                wanted.entry(c).or_default().extend(p);
            }
            own_removals = own;
            wanted
        };
        for (c, want) in wanted {
            let (mine, have) = self.held_parts(g, l, &c)?;
            // what the label's closure bodies carry is never copied (a copy duplicating closure
            // parts is a strict subset others delete), but a removal's own parts: no body carries
            // them once the label's actor reads the thing no more
            let inside = if own_removals.contains(&c) { Default::default() } else { self.engine.header(&c).map(|h| inside(&h, &closure)).unwrap_or_default() };
            let missing: BTreeSet<(usize, usize)> = want.difference(&have).filter(|(ai, _)| !inside.contains(ai)).copied().collect();
            // this node's own copy placed before and gone since (deleted at the host): not
            // placed again, but for its own card while it reads the label's actor (admins delete
            // a departed node's card; a re-grant wants it back, spec/permissions.md §4)
            if missing.is_empty() || mine.is_empty() && self.state.certs.contains(&(l, c)) && !self.own_card_read(g, &c, &missing) {
                continue;
            }
            // another node's demotion or new `keys.0` received less than `SETTLE_MS` ago is its
            // author's to place (spec/permissions.md §3, §4): holders that learn of it under
            // another label first do not all copy it; a wake brings the pass back then
            let me = self.engine.tid();
            let now = self.now();
            let due = self.engine.core.ix.commits.get(&c).filter(|m| m.header.author != me).map(|m| m.received.0.saturating_add(SETTLE_MS)).filter(|t| *t > now);
            if let Some(t) = due
                && let Some(h) = self.engine.header(&c)
                && (h.frontier.is_some() || missing.iter().all(|(ai, _)| h.aspects.get(*ai).is_some_and(|a| a.ak.as_str() == "keys.0")))
            {
                let at = self.raw_now().saturating_add(t - now);
                self.settle_by(at);
                continue;
            }
            // nothing to place once its parts are dropped here (`State::sweep_certs`)
            let bodies = self.engine.part_bodies(&c, &missing)?;
            if bodies.is_empty() {
                continue;
            }
            for b in bodies {
                self.place(g, l, &b, true)?;
            }
            self.place_linked(l, &c, &missing)?;
            self.state.add_cert(l, c);
        }
        Ok(())
    }

    /// Whether `parts` of `c` are this node's own card (its `node.0`, `reach.0`, `keys.0` writes)
    /// and it currently reads `g`'s actor.
    fn own_card_read(&self, g: &Tid, c: &CommitId, parts: &BTreeSet<(usize, usize)>) -> bool {
        let me = self.engine.tid();
        let Some(h) = self.engine.header(c) else { return false };
        h.author == me && parts.iter().all(|(ai, _)| h.aspects.get(*ai).is_some_and(|a| a.tid == me && is_card(a.ak.as_str()))) && self.engine.core.may_read(&me, &self.engine.group_actor(g))
    }

    /// Whether entries under `l` already hold every delta of `c` on aspects `ais` (another
    /// holder's copy of the same grant counts: spec/permissions.md §4), so a copy would only be
    /// a duplicate.
    fn held_whole(&mut self, g: &Tid, l: LabelId, c: &CommitId, ais: &BTreeSet<usize>) -> Result<bool> {
        let Some(h) = self.engine.header(c) else { return Ok(false) };
        let want = parts_of(&h, |i| ais.contains(&i));
        let (_, held) = self.held_parts(g, l, c)?;
        Ok(want.is_subset(&held))
    }

    /// The parts of commit `c` entries under `l` hold, as (this node's certificate copies, all
    /// that count): another node's copy or body counts once genuine and present at every host
    /// this node syncs the label with, and, carrying a rotation of the label's actor, only if it
    /// opens under the newest read secret (spec/permissions.md §4). Not `held_at` (whether this
    /// node's own commit is placed).
    fn held_parts(&mut self, g: &Tid, l: LabelId, c: &CommitId) -> Result<(Parts, Parts)> {
        let hosts: Vec<HostKey> = self.conns.values().filter(|x| x.labels.contains_key(&l)).map(|x| x.host).collect();
        self.held_parts_at(g, l, c, Some(&hosts))
    }

    /// `held_parts` with another node's entries counted when present at each of `hosts`
    /// (`None`: this node's own served state, a label served with no host: every entry).
    fn held_parts_at(&mut self, g: &Tid, l: LabelId, c: &CommitId, hosts: Option<&[HostKey]>) -> Result<(Parts, Parts)> {
        let newest = self.engine.wrap_secret(g, None)?;
        let mut mine: BTreeSet<(usize, usize)> = BTreeSet::new();
        let mut others: Vec<(BlobId, Vec<(usize, usize)>)> = Vec::new();
        for (id, e) in self.state.entries_of(&l, c) {
            let Kind::Commit { parts, .. } = &e.kind else { continue };
            if e.cert {
                mine.extend(parts.iter().copied());
            } else if hosts.is_none_or(|ss| !ss.is_empty() && ss.iter().all(|s| self.state.holds_at(s, &l, &id)))
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
    fn heartbeat(&mut self, g: &Tid, l: LabelId, keys: &HeadKeys, tight: bool, closure: &BTreeSet<Tid>) -> Result<()> {
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
        let suspect = self.suspects_under(closure)?;
        let Some(c) = self.heartbeat_commit(false, suspect)? else { return Ok(()) };
        let ais = BTreeSet::from([0usize]);
        for b in self.engine.partial_bodies(&c, &ais)? {
            self.place(g, l, &b, true)?;
        }
        self.state.set_beat(l, now);
        Ok(())
    }

    /// The aspects of things in a label's `closure` this node flags suspect, with their keyed
    /// state digests (spec/permissions.md §4): the most recently flagged first, at most
    /// `MAX_HEARTBEAT_SUSPECTS`; an aspect with no digest here (no state, no creation record)
    /// waits until it has one. Only the label's things: its readers learn nothing of others.
    fn suspects_under(&mut self, closure: &BTreeSet<Tid>) -> Result<BTreeSet<ct::Suspect>> {
        let mut flagged: Vec<(Tid, Ak, u64, u8)> = self.engine.suspects()?.into_iter().filter(|x| closure.contains(&x.0)).collect();
        flagged.sort_by_key(|x| std::cmp::Reverse(x.2));
        let mut out = BTreeSet::new();
        for (tid, ak, _, _) in flagged {
            if out.len() >= osis_base::format::MAX_HEARTBEAT_SUSPECTS {
                break;
            }
            if let Some(digest) = self.engine.state_digest(&tid, &ak)? {
                out.insert(ct::Suspect { thing: tid, ak: ak.as_str().to_string(), digest });
            }
        }
        Ok(out)
    }

    /// A `seen.0` commit on this node reporting `suspect` (spec/permissions.md §4): reused
    /// within the interval, whatever it reports (at most one heartbeat per interval; a flag
    /// raised since waits for the next).
    pub(crate) fn heartbeat_commit(&mut self, stranded: bool, suspect: BTreeSet<ct::Suspect>) -> Result<Option<CommitId>> {
        let me = self.engine.tid();
        let now = self.now();
        if !stranded
            && let Some(c) = self.engine.core.ix.by_aspect.get(&(me, Ak::new("seen.0").map_err(|_| crate::Error::Misuse("ak"))?)).and_then(|s| s.iter().next_back()).map(|x| x.1)
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
        m.replace(me, &ct::SEEN, &ct::Seen { ts: WallMs(ts), stranded, suspect })?;
        m.expires(me, &ct::SEEN, WallMs(ts.saturating_add(life)))?;
        self.engine.commit(m)
    }

    /// A stranded heartbeat (spec/permissions.md §4; spec/sync.md §5): the label cannot be read
    /// here; deposited, wrapped under the newest established read secret held, no open needed.
    /// Only under the deposit key of the host's head as this node knows it: a deposit seed that
    /// does not derive it (an actor whose `keys.0` has not arrived yet, a link's K seen as
    /// deriving from its owner) is refused, so nothing is sent.
    pub(crate) fn stranded(&mut self, conn: ConnId, g: Tid, l: LabelId, out: &mut Vec<super::Action>) -> Result<()> {
        if self.state.stranded.get(&l).is_some_and(|t| t.saturating_add(HEARTBEAT_MIN_INTERVAL_MS) > self.now()) {
            return Ok(());
        }
        let Some(host) = self.conns.get(&conn).map(|c| c.host) else { return Ok(()) };
        let Some(head) = self.lc(conn, &l).and_then(|x| x.head.clone()).or_else(|| self.state.heads.get(&(host, l)).cloned()) else { return Ok(()) };
        let Some(seed) = self.engine.deposit_seed(&g)? else { return Ok(()) };
        let d = osis_crypto::deposit_key(&seed, &l);
        if d.verifying_key() != head.keys.deposit {
            return Ok(());
        }
        let Some(secret) = self.engine.stranded_secret(&g) else { return Ok(()) };
        let Some(c) = self.heartbeat_commit(true, BTreeSet::new())? else { return Ok(()) };
        for b in self.engine.partial_bodies(&c, &BTreeSet::from([0usize]))? {
            let s = seal_body(&b, &mut *self.rng)?;
            let wrap = osis_crypto::wrap(&secret, &s.id, &s.key)?;
            let sig = osis_label::sign_deposit(&d, &l, &s.id, &wrap);
            self.command(conn, Command::Deposit { label: l, blob: s.blob, wrap, sig }, out)?;
        }
        let now = self.now();
        self.state.set_stranded(l, now);
        Ok(())
    }

    /// Re-registration (spec/sync.md §5): an admin holding the head's epochs and a newer
    /// established one uploads the actor's role commits the host lacks under the head's
    /// keys, then registers a child step; the rest of the pass runs once it is registered, or
    /// under the host's head while the step is refused for now. True while the step is in flight.
    fn reregister(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<super::Action>) -> Result<bool> {
        let Some(c) = self.conns.get(&conn) else { return Ok(false) };
        let host = c.host;
        let Some(lc) = c.labels.get(&l) else { return Ok(false) };
        let (g, keys, head, retry) = (lc.group, lc.keys.clone(), lc.head.clone(), lc.step_retry);
        // a replaced label is never stepped again (spec/sync.md §2: its replacement carries on)
        if !self.step_due(&g, &l, &keys) {
            return Ok(false);
        }
        // a step refused for now goes again only after its back-off; meanwhile the pass runs
        // under the host's head: what it uploads is wrapped under the newest read epoch, so a
        // removed holder still opening that head gets nothing it can read (spec/sync.md §5)
        if retry > self.raw_now() {
            return Ok(false);
        }
        let (Some(write), Some(head)) = (keys.write.clone(), head) else { return Ok(false) };
        let a = self.engine.core.secret_actor(&g).unwrap_or(g);
        let core = &self.engine.core;
        let ids: Vec<CommitId> = core.ix.by_thing.get(&a).into_iter().flatten().filter(|c| core.ix.commits.get(c).is_some_and(|m| m.view.kind.is_role())).copied().collect();
        let mut uploads = Vec::new();
        for id in ids {
            for b in self.engine.bodies(&id)? {
                if b.reader != a && !self.engine.core.may_read(&a, &b.reader) {
                    continue;
                }
                let bid = match self.entry_for(Some(&host), &l, &b) {
                    Some(x) => x,
                    None => match self.place(&g, l, &b, false)? {
                        Some(x) => x,
                        None => continue,
                    },
                };
                if self.state.is_present(&host, &l, &bid) {
                    continue;
                }
                let (Some(en), Some(blob)) = (self.state.entries.get(&(l, bid)).cloned(), self.engine.blob(&bid)?) else { continue };
                let stamp = osis_label::sign_stamp(&write, &l, &bid, &en.wrap);
                uploads.push(osis_proto::Entry { blob, wrap: en.wrap, stamp, replaces: Vec::new() });
            }
        }
        if !uploads.is_empty() {
            self.command(conn, Command::Upload { label: l, entries: uploads }, out)?;
        }
        // a child of the host's head already recorded in `label.0` (this node's local step,
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

    /// A child of step `head` recorded in `label.0` with its claim set (the lowest ID among
    /// several).
    fn recorded_child(&mut self, g: &Tid, l: &LabelId, head: &osis_label::StepId) -> Option<(osis_label::Step, osis_label::ClaimSet)> {
        let gl = self.group_label(g, l)?;
        gl.steps.values().filter_map(|(s, c)| c.clone().map(|c| (s.clone(), c))).filter(|(s, _)| s.prev == Some(*head)).min_by_key(|(s, _)| s.id())
    }
}
