//! The pass at one host for one label after its log was read to the end (spec/sync.md §5-§7;
//! spec/permissions.md §4): re-registration first when this admin holds newer epochs than the
//! head (the actor's role commits the host lacks, then the step; the rest after it is
//! registered), then uploads of must-hold bodies (role commits first) or relays of stamped ones,
//! this node's certificates and node card, and deletions of must-not-hold bodies (`delete`: by
//! the label delete key or a delete key, carriers first), then re-seals (`reseal`).

mod bodies;
mod certs;
mod delete;
mod inbox;
mod promote;
mod register;
mod reseal;

use super::state::{BlobRec, Entry, Kind, HostKey, Touch};
use super::work::{Inputs, Left, Note, Scope, Work};
use super::{ConnId, SyncEngine};
use crate::error::Result;
use crate::labeling::{Body, BodyCtx, Facts, HeadKeys, Hold, Parts, Why, classify, delete_item, delete_item_by_level, may_delete};
use osis_commit::Kind as CKind;
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
/// places it as its own chain certificate, and a plain thing with a holder to the author of its
/// newest edge write before this node gives it secrets of its own (ms; `settle_by` brings the
/// pass back after). Minor consequence: at 0 nodes duplicate the work (a copy each, a fork of the
/// thing's secrets each); at infinity what an absent author left is never done.
const SETTLE_MS: u64 = 30_000;

/// The least a writer waits, after receiving another node's commit or seeing a deposit, before
/// it uploads or promotes it itself (ms); the most is `SETTLE_MS`. The point in between is this
/// node's per blob (`relay_delay`), so the author or the first co-writer is usually done and the
/// others skip it: writers online together otherwise each sent a copy (spec/sync.md §6, §7).
const RELAY_MIN_MS: u64 = 5_000;

/// An entry to send, by priority (role and certificates before content).
struct Out {
    prio: u8,
    id: BlobId,
    /// Placed by this pass (a new encryption, or a linked blob's entry added).
    fresh: bool,
    /// What is judged again until the host has it (`Left`).
    of: Option<Touch>,
}

/// Chunks of dropped deltas with the commit and chunk entry listing them, and whether the
/// blob's held prefix bears the entry (`dropped_chunks`).
type DroppedChunks = BTreeMap<BlobId, (CommitId, osis_commit::ChunkEntry, bool)>;

/// The bodies wanted under a label, by commit (`judge`).
type Desired = BTreeMap<CommitId, Vec<Vec<usize>>>;

fn desired(bodies: &[Body]) -> Desired {
    let mut m: Desired = BTreeMap::new();
    for b in bodies {
        m.entry(b.commit).or_default().push(b.parts.clone());
    }
    m
}

/// Whether an entry's live writes are carried, and the aspects only a snapshot can carry
/// (`SyncEngine::carried`).
type Carriage = (bool, Vec<(Tid, Ak)>);

/// What may become of an entry judged under a label (`SyncEngine::deletable`).
#[allow(clippy::large_enum_variant)] // short-lived, one per judged entry
enum Fate {
    /// Not must-not-hold, or not judged.
    Keep,
    /// Must-not-hold, but its live writes wait for a carrier (a covering snapshot was asked
    /// for), or this node holds no delete item for it.
    Wait,
    /// Goes, for this reason, by this delete item.
    Delete(Why, osis_label::DeleteItem),
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
pub(crate) struct Head {
    pub(crate) g: Tid,
    pub(crate) l: LabelId,
    pub(crate) host: Option<HostKey>,
    pub(crate) id: osis_label::StepId,
    /// The head's write key: the stamps it takes (spec/sync.md §5 Stamp).
    pub(crate) stamps: osis_crypto::VerifyingKey,
    pub(crate) keys: HeadKeys,
    pub(crate) read_ok: bool,
}

impl Head {
    fn at<'a>(&'a self, snaps: &'a Snaps, settled: bool, roles_behind: bool) -> At<'a> {
        At { g: self.g, l: self.l, host: self.host, keys: &self.keys, snaps, settled, roles_behind }
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
    /// A role commit or request this node must hold under the label is not at the source yet
    /// (its relay waits, or the source has not pulled it): deletions there wait (`deletions`).
    roles_behind: bool,
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
    ct::is_role_class(ak) || matches!(ak, "created.0" | "node.0" | "reach.0")
}

/// Every part of `h` on the aspects `keep` admits.
pub(crate) fn parts_of(h: &osis_commit::Header, keep: impl Fn(usize) -> bool) -> BTreeSet<usize> {
    (0..h.aspects.len()).filter(|i| keep(*i)).collect()
}

/// The aspect indexes of `h` on things of `closure` (what the label's closure bodies carry).
fn inside(h: &osis_commit::Header, closure: &BTreeSet<Tid>) -> BTreeSet<usize> {
    h.aspects.iter().enumerate().filter(|(_, a)| closure.contains(&a.tid)).map(|(i, _)| i).collect()
}

/// Send `o` is judged again by the next pass.
fn leave(o: &Out, left: &mut Left) {
    match o.of {
        Some(Touch::Commit(c)) => {
            left.commits.insert(c);
        }
        Some(Touch::Blob(b)) => {
            left.blobs.insert(b);
        }
        None => left.again = true,
    }
}

fn leave_all(sends: &[Out], left: &mut Left) {
    for o in sends {
        leave(o, left);
    }
}

impl SyncEngine {
    /// When time alone next wants a pass of `l` (`Work::pass_at`): a due time of the work set or
    /// the roster's clock horizon; with neither, none (a label passes when marked).
    fn schedule_pass(&mut self, l: LabelId) {
        let now = self.now();
        let full_passes = self.cfg.full_passes;
        let w = self.work_mut(l);
        let t = w.waits.due.keys().next().into_iter().chain(w.until.as_ref()).copied().min();
        w.pass_at = if full_passes { Some(0) } else { t };
        w.scheduled = now;
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

    /// Runs a pass of `l` of `g` over its work set: the closure synced and the engine's changes
    /// spread first; what touches the set during the pass collects in its place and joins it
    /// after; a failed pass judges everything next time.
    fn with_work(&mut self, g: &Tid, l: LabelId, f: impl FnOnce(&mut Self, &BodyCtx, &mut Work) -> Result<()>) -> Result<()> {
        // this group's closure is synced (spec/sync.md §3)
        if !self.engine.core.ix.syncing.contains(g) {
            self.engine.set_syncing(*g, true)?;
        }
        // the group's closure, taken once for the pass
        let ctx = self.engine.body_ctx(g);
        // what an earlier pass of this step changed in the engine (a carrier snapshot written)
        self.engine_events()?;
        self.spread_touches();
        let mut w = std::mem::take(self.work_mut(l));
        let r = f(self, &ctx, &mut w);
        if r.is_err() {
            w.touched.full = true;
        }
        let x = self.work_mut(l);
        let meanwhile = std::mem::replace(x, w);
        x.merge(meanwhile);
        r
    }

    /// The work set of `l` (made when missing).
    pub(super) fn work_mut(&mut self, l: LabelId) -> &mut Work {
        self.work.entry(l).or_insert_with(Work::fresh)
    }

    /// Stamps entry `id` under `l` and keeps the stamp, so a later pass does not promote it again.
    pub(super) fn stamp_entry(&mut self, l: LabelId, id: BlobId, mut e: Entry, write: &osis_crypto::SigningSecret) -> osis_crypto::Signature {
        let stamp = osis_label::sign_stamp(write, &l, &id, &e.wrap);
        e.stamp = Some(stamp);
        self.state.set_entry(l, id, e);
        stamp
    }

    /// Readies `w` for a pass (`prepare`): whether it judges everything, and its scope.
    fn begin(&mut self, g: &Tid, l: &LabelId, w: &mut Work, closure: &std::sync::Arc<BTreeSet<Tid>>) -> (bool, Scope) {
        let full = self.prepare(g, l, w, closure);
        self.stats.passes += 1;
        w.passes += 1;
        let scope = if full { Scope::All } else { Scope::Some { commits: std::mem::take(&mut w.touched.commits), blobs: std::mem::take(&mut w.touched.blobs) } };
        (full, scope)
    }

    /// What a pass judges: the scope with what touched the set meanwhile, the unsettled sets
    /// and the inputs taken (`take_inputs`), the label's snapshots with the bodies they cover
    /// dropped, and the bodies of the scope. Entries get their linked prefixes checked.
    fn judging(&mut self, p: &Head, ctx: &BodyCtx, w: &mut Work, mut scope: Scope, full: bool) -> Result<J> {
        let (g, l, keys) = (&p.g, p.l, &p.keys);
        self.pull(g, l, &mut scope, w);
        self.check_linked_prefixes(l, &scope)?;
        let fetching = w.unopened.iter().any(|b| self.asked_for(l, b));
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
        if self.take_inputs(p, w, &mut scope, full, inputs, &sets) && !full {
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

    /// The pass inputs and unsettled sets of `w` (`judge`): a changed
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

    /// The passes (spec/sync.md §5): every label this node syncs gets one pass per change,
    /// whatever the number of its sources. Its own part runs once against this node's store
    /// (placing what the label must hold of its own, certificates, stamping, promotion,
    /// deletions there, re-seals, a step when it has no source); then, per source (a peer that
    /// cannot read the label, `sources`), registration, deletes and clearing over what that
    /// peer's stream showed it (`known`). Readers pull this node's store, and so do sources.
    /// Runs while a peer can pull this node (`serves_readers`) or a source is connected.
    pub(crate) fn passes(&mut self, out: &mut Vec<super::Action>) -> Result<()> {
        let all = std::mem::take(&mut self.pass_due);
        let due = std::mem::take(&mut self.due_labels);
        let own_wrote = std::mem::take(&mut self.own_wrote);
        let fill_due = std::mem::take(&mut self.fill_due);
        if all {
            self.passed_at = self.now();
        }
        let sourced = self.conns.values().any(|c| c.labels.values().any(|x| x.phase == super::Phase::Open));
        if !sourced && !self.serves_readers() {
            self.passing = false;
            return Ok(());
        }
        let labels: Vec<(Tid, LabelId, u64)> = self.labels().into_iter().map(|(g, l)| (g, l.id, l.index)).collect();
        self.passing = !labels.is_empty();
        if labels.is_empty() {
            return Ok(());
        }
        let served = self.served_labels();
        self.work.retain(|x, _| labels.iter().any(|(_, l, _)| l == x));
        for (g, l, index) in labels {
            if !all && !due.contains(&l) && !fill_due.contains(&l) {
                continue;
            }
            let Some(head) = served.get(&l).and_then(|s| s.head()) else { continue };
            // no pass before a fill has what judging needs: it would ask what it lacks at once,
            // out of the fill's order (`read_first`); one under way passes at its own times
            // (`fill_due`) and on this node's own writes, not per batch applied
            if self.fill_first_waits(&l) || self.filling(&l) && !own_wrote && !fill_due.contains(&l) {
                continue;
            }
            // one label's failure stops neither the others nor the handle
            if let Err(e) = self.label_pass(g, l, index, head, out) {
                self.diag(format!("pass of {l:?}: {e}"));
            }
            self.schedule_pass(l);
        }
        Ok(())
    }

    /// The sources of `l` a pass acts on: connected peers that cannot read it where this node
    /// opened it by a sync-key or claim Hit and whose stream read it to their log's end, with
    /// nothing registering there.
    pub(crate) fn sources(&self, l: &LabelId) -> Vec<ConnId> {
        self.conns.iter().filter(|(id, c)| c.up && c.labels.get(l).is_some_and(|x| x.phase == super::Phase::Open && x.ready()) && self.read_as_host(**id, l)).map(|(id, _)| *id).collect()
    }

    /// The keys of `head` this node may use, and whether it may place under read: never encrypt
    /// under a blocked epoch, so rotate first (flows' cascade), else hold back what the blocked
    /// roles would sign or wrap. Read blocked for encrypting but not for placing leaves only
    /// certificates and the node's own role commits to place (no write key: nothing fresh else).
    fn usable_keys(&mut self, g: &Tid, index: u64, head: &osis_label::Step) -> Result<(HeadKeys, bool)> {
        let mut keys = self.engine.head_keys(g, index, head)?;
        let still = self.uncovered(g, true)?;
        let read = still.encrypt.contains(&Role::Read);
        if read || still.encrypt.contains(&Role::Write) {
            keys.write = None;
        }
        if read || still.encrypt.contains(&Role::Admin) {
            keys.delete = None;
        }
        if read {
            keys.sync_established = false;
        }
        Ok((keys, !still.place.contains(&Role::Read)))
    }

    /// One label's pass: with no source, a newer established epoch first issues a child step of
    /// the served head when that head is recorded in `label.0` (recorded there, so the served
    /// head moves; `reregister` registers it at a source later), and the pass goes on under it.
    fn label_pass(&mut self, g: Tid, l: LabelId, index: u64, head: &osis_label::Step, out: &mut Vec<super::Action>) -> Result<()> {
        let _s = crate::costs::span("pass");
        let (mut keys, read_ok) = self.usable_keys(&g, index, head)?;
        let recorded = self.group_label(&g, &l).is_some_and(|gl| gl.steps.contains_key(&head.id()));
        if self.sources(&l).is_empty() && recorded && self.step_due(&g, &l, &keys) && self.step_settled(&g, l) {
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
        // no secret of the served head's sync epoch: each source is read first, then the label
        // reported stranded there (`at_source`)
        let own = read_ok && keys.epochs[0].is_some() && (keys.is_writer() || keys.deposit.is_some());
        let p = Head { g, l, host: None, id: head.id(), stamps: head.keys.write, keys, read_ok };
        self.with_work(&g, l, |s, ctx, w| s.run_pass(&p, own, ctx, w, out))
    }

    /// The pass after the keys and the step (`label_pass`), over what work set `w` names, or
    /// everything when it says so or an input of the pass changed. `own`: this node may place
    /// under the label (a read epoch of the head held, and a write or deposit key).
    fn run_pass(&mut self, p: &Head, own: bool, ctx: &BodyCtx, w: &mut Work, out: &mut Vec<super::Action>) -> Result<()> {
        let (g, l, keys) = (p.g, p.l, &p.keys);
        let sources = self.sources(&l);
        if sources.iter().any(|c| !w.acted.contains(c)) {
            w.touched.full = true;
        }
        let (full, scope) = self.begin(&g, &l, w, &ctx.closure);
        let J { mut scope, mut left, snaps, mut bodies, judged, unsettled, snapping, replaced } = self.judging(p, ctx, w, scope, full)?;
        let mut sends = Vec::new();
        // a role commit this node must hold waits for its relay (`relay_at`): no source has it
        // from here yet
        let mut behind = false;
        if own {
            sends = self.body_sends(p, &bodies, &snaps, &snapping, &mut left, &mut behind)?;
            self.relay_now.remove(&l);
            let ours: BTreeSet<BlobId> = sends.iter().filter(|o| o.fresh).map(|o| o.id).collect();
            if !replaced {
                let authors: BTreeSet<Tid> = w.unjudged.values().copied().collect();
                self.certificates(&g, l, &authors)?;
            }
            if let Some(wk) = &keys.write {
                self.local_promote(&g, l, wk, &scope, &ours, &mut left)?;
            }
            // what the placements just made touched (certificate copies)
            self.pull(&g, l, &mut scope, w);
            sends.extend(self.cert_sends(l, &scope));
            if let Some(wk) = &keys.write {
                // stamped as placed (another node's deposits: `local_promote`; inbox blobs it
                // stamps: `stamp_inbox`)
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
                self.stamp_inbox(l, &scope, wk)?;
            }
        }
        let settled = unsettled.is_empty();
        self.judge_touched(ctx, &g, &l, &scope, &judged, &mut bodies)?;
        w.acted.clear();
        for conn in sources {
            if self.at_source(conn, p, w, (&sends, behind), &bodies, &snaps, &scope, settled, &mut left, out)? {
                w.acted.insert(conn);
            }
        }
        if own {
            // what this node's store must not hold goes, whoever else holds the label
            self.local_deletions(&p.at(&snaps, settled, false), &bodies, &scope, &mut left)?;
            self.reseal(&g, l)?;
        }
        w.leave(left);
        Ok(())
    }

    /// The pass's part at source `conn` (a peer that cannot read `l`, read to its end): what it
    /// holds is what its stream showed (`known`). A head whose read epoch this node holds no
    /// secret of: read there first, else stranded. Then re-registration (`reregister`); this
    /// node's own deposits it lacks go as Deposit items, and, at a writer on the source's head,
    /// what it lacks stamped under a superseded key is stamped again (it pulls them); deposits
    /// it keeps waiting are cleared, and must-not-hold entries it holds deleted by a delete-key
    /// holder, once it holds the role commits this node must hold there. Whether it acted there
    /// (not while registering or reading first: the next pass with it judges everything).
    #[allow(clippy::too_many_arguments)]
    fn at_source(&mut self, conn: ConnId, own: &Head, w: &Work, (sends, behind): (&[Out], bool), bodies: &[Body], snaps: &Snaps, scope: &Scope, settled: bool, left: &mut Left, out: &mut Vec<super::Action>) -> Result<bool> {
        let (g, l) = (own.g, own.l);
        let Some(c) = self.conns.get(&conn) else { return Ok(false) };
        let host = c.host;
        let Some(lc) = c.labels.get(&l) else { return Ok(false) };
        let (index, Some(head)) = (lc.index, lc.head.clone()) else { return Ok(false) };
        // secrets may have arrived since the head was accepted
        self.recheck_doubts();
        let (keys, read_ok) = self.usable_keys(&g, index, &head)?;
        if let Some(lc) = self.lc_mut(conn, &l) {
            lc.keys = keys.clone();
        }
        // no secret of the head's sync epoch: read first (spec/sync.md §5, reading without it),
        // stranded only once nothing more here opens
        if keys.epochs[0].is_none() {
            if self.read_first(conn, host, &g, l, out)? {
                leave_all(sends, left);
                return Ok(false);
            }
            self.stranded(conn, g, l, out)?;
            return Ok(true);
        }
        // registering there: what this pass would act on there waits for the next one. A step
        // goes once the source has read, under its head, the role commits it lacks (a removed
        // reader reads its removal only there); the rest of the pass runs meanwhile
        let unreported = self.roles_unreported(conn, l, sends)?;
        if let Some(lc) = self.lc_mut(conn, &l) {
            lc.report_at = unreported;
        }
        if unreported.is_none() && self.reregister(conn, l, out)? {
            leave_all(sends, left);
            return Ok(false);
        }
        self.refetch(conn, host, l, w, out)?;
        let p = Head { g, l, host: Some(host), id: head.id(), stamps: head.keys.write, keys, read_ok };
        let lacks = |s: &Self, id: &BlobId| !s.state.is_present(&host, &l, id) && !s.state.is_gone_at(&host, &l, id);
        let mut roles_behind = behind;
        let mut deposits = Vec::new();
        let on_head = p.id == own.id;
        let again = self.encrypt_again(host, own, (sends, behind), bodies, snaps, left)?;
        for o in sends.iter().chain(&again) {
            if !lacks(self, &o.id) {
                continue;
            }
            // judged again next pass until the source has it
            leave(o, left);
            let Some(e) = self.state.entries.get(&(l, o.id)).cloned() else { continue };
            let stamped = e.stamp.is_some_and(|s| osis_label::verify_stamp(&p.stamps, &l, &o.id, &e.wrap, &s).is_ok());
            // a role commit the source takes once it pulls it; at a source on an older head
            // (its step waits or was refused for now) nothing waits for the step, deletes
            // included (they may be what frees room for it)
            roles_behind |= o.prio <= 1 && p.keys.is_writer() && on_head;
            match &own.keys.write {
                Some(wk) if on_head && !stamped => {
                    self.stamp_entry(l, o.id, e, wk);
                }
                // a source on an older head (its step refused for now, spec/sync.md §5) takes
                // what is stamped for its head: stamped for it unless the stamp already serves
                // another source, which keeps it (its head moving judges everything again)
                Some(_) if !stamped && !self.stamp_serves_a_source(l, o.id, &e) => {
                    if let Some(wk) = &p.keys.write {
                        self.stamp_entry(l, o.id, e, wk);
                    }
                }
                Some(_) => {}
                None if !stamped && (self.mine(&e) || matches!(o.of, Some(Touch::Commit(_)))) => deposits.push(o.id),
                None => {}
            }
        }
        self.deposit_items(conn, &p, deposits, out)?;
        self.clear_deposits(conn, host, &p, out)?;
        let quiet = self.is_replaced(&g, &l) && sends.iter().all(|o| !lacks(self, &o.id));
        self.deletions(conn, &p.at(snaps, settled, roles_behind), bodies, scope, left, out)?;
        if quiet && settled {
            self.retire_at(host, &g, l)?;
        }
        Ok(true)
    }

    /// The node log position source `conn` must report reading `l` to before a step is
    /// registered there: the last first-logged position of a role commit it lacks; `None` when it
    /// read them all (taken, or refused: a full peer's step must not wait for room).
    fn roles_unreported(&mut self, conn: ConnId, l: LabelId, sends: &[Out]) -> Result<Option<u64>> {
        let Some(host) = self.conns.get(&conn).map(|c| c.host) else { return Ok(None) };
        let lacking: Vec<BlobId> = sends.iter().filter(|o| o.prio <= 1 && !self.state.is_present(&host, &l, &o.id) && !self.state.is_gone_at(&host, &l, &o.id)).map(|o| o.id).collect();
        if lacking.is_empty() {
            return Ok(None);
        }
        let reported = self.stream_reported(conn, &l);
        // placed this pass: logged now, so their positions are known
        self.state.flush(&mut self.engine)?;
        let at = self.engine.run(|tx| {
            let mut at = None;
            for b in &lacking {
                if let Some(p) = super::state::hub(tx)?.node_log(|t| t.log_entry_first(&l, b))? {
                    at = at.max(Some(p));
                }
            }
            Ok(at)
        })?;
        Ok(at.filter(|p| reported.is_none_or(|r| r < *p)))
    }

    /// Whether entry `id`'s stamp verifies under the head of a source of `l`.
    fn stamp_serves_a_source(&self, l: LabelId, id: BlobId, e: &Entry) -> bool {
        let Some(stamp) = e.stamp else { return false };
        self.sources(&l).iter().filter_map(|c| self.lc(*c, &l)?.head.as_ref().map(|h| h.keys.write)).any(|k| osis_label::verify_stamp(&k, &l, &id, &e.wrap, &stamp).is_ok())
    }

    /// Must-hold bodies whose entry source `host` deleted while this node's judgment finds the
    /// delete does not stand (`delete_stands`), or holds under a wrap of no use: the source
    /// refuses that blob ID while its tombstone lasts, or keeps its stamped wrap, so each is encrypted again (`place`) and the old entry dropped here; the
    /// source pulls the new one. While a role commit this node must hold waits for its relay
    /// (`behind`), the deleter may judge by an older role view: nothing is encrypted again and
    /// the label's role commits are placed at once instead (`relay_now`), so the source learns
    /// them first (issues: churn seed 361's storm).
    fn encrypt_again(&mut self, host: HostKey, own: &Head, (sends, behind): (&[Out], bool), bodies: &[Body], snaps: &Snaps, left: &mut Left) -> Result<Vec<Out>> {
        let (g, l) = (own.g, own.l);
        let mut again = Vec::new();
        let mut note = Note::default();
        for o in sends {
            let Some(Touch::Commit(c)) = o.of else { continue };
            // gone there: deleted, or held under a wrap of no use (`set_gone`)
            if !self.state.is_gone_at(&host, &l, &o.id) {
                continue;
            }
            let Some((Kind::Commit { parts, .. }, cert)) = self.state.entries.get(&(l, o.id)).map(|e| (e.kind.clone(), e.cert)) else { continue };
            // a certificate copy: another copy of the same parts unless a genuine entry held
            // there carries them (the delete stands: a duplicate went); a body: when its delete
            // does not stand and no other encryption held there carries it
            let b = if cert {
                let held: Vec<BlobId> = self.state.entries_of(&l, &c).filter(|(id, e)| matches!(&e.kind, Kind::Commit { parts: p, .. } if parts.iter().all(|x| p.contains(x))) && self.state.holds_at(&host, &l, id)).map(|(id, _)| id).collect();
                if held.into_iter().any(|id| self.genuine(&id)) {
                    continue;
                }
                let Some(h) = self.engine.header(&c) else { continue };
                Body { commit: c, parts: parts.clone(), expires: None, blind: h.blind, plaintext: Vec::new(), role_commit: h.kind.is_role(), order: h.ts.to_u64().max(1), to_label: false }
            } else {
                let readable = self.readable(&g, &c, &parts);
                let Some(b) = bodies.iter().find(|b| b.commit == c && b.parts == readable).cloned() else { continue };
                if self.delete_stands(Some(&host), l, &b, &b.parts, snaps, &mut note)? || self.entry_for(Some(&host), &l, &b).is_some_and(|x| self.state.is_present(&host, &l, &x)) {
                    continue;
                }
                note.leave(c, left);
                b
            };
            left.commits.insert(c);
            if behind {
                self.relay_now.insert(l);
                continue;
            }
            let Some(id) = self.place(&g, l, &b, cert)? else { continue };
            if cert {
                self.place_linked(l, &c, &parts.iter().copied().collect())?;
                self.state.add_cert(l, c);
            }
            // a useless entry the source holds stays known until its delete there (`judge`: the
            // useless one goes, whatever the IDs)
            if !self.state.is_present(&host, &l, &o.id) {
                self.state.drop_entry(l, o.id);
            }
            again.push(Out { prio: o.prio, id, fresh: true, of: o.of });
        }
        Ok(again)
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
                // a forgotten memory commit lists its pages by the header kept for it
                let listed = commits.iter().filter_map(|c| self.engine.header(c).or_else(|| self.memory.forgotten.get(c).map(|f| f.header.clone()))).flat_map(|h| h.chunks.iter().map(|ch| ch.blob).collect::<Vec<_>>());
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

    /// The prefix expiry of blob `b` held here: an entry placed of it records it at once
    /// (`Entry::expires`, `expire_entries`).
    pub(crate) fn held_expiry(&mut self, b: &BlobId) -> Result<Option<u64>> {
        Ok(self.engine.blob(b)?.and_then(|x| osis_label::Prefix::parse(&x).ok()).and_then(|p| p.expiry()).map(|t| t.0))
    }

    /// Drops the bytes of a blob whose entry under a label synced with nobody went: a commit
    /// blob's record and bytes once no entry names it, any other blob's bytes likewise.
    pub(crate) fn forget_entry_blob(&mut self, id: &BlobId) -> Result<()> {
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
                // the work set holds what the snapshot may drop (with a new one, the aspect's
                // cover candidates, `work::prepare`); a full pass judges every body
                let only: Option<Vec<CommitId>> = match &*scope {
                    Scope::Some { commits, .. } => Some(commits.iter().filter(|c| self.engine.header(c).is_some_and(|h| h.aspects.iter().any(|x| x.tid == *t && x.ak == *a))).copied().collect()),
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
        let busy = ids.iter().any(|b| self.asked_for(l, b));
        Ok(self.open_or_fetch(conn, host, l, ids, out)? || busy)
    }

    /// Of unopened entries `ids` of `l`: those whose bytes are here are opened under the
    /// secrets held now, the rest present at `host` fetched (a fetch lost to a cut or crash,
    /// secrets that arrived later). Whether any was fetched or opened.
    fn open_or_fetch(&mut self, conn: ConnId, host: HostKey, l: LabelId, ids: Vec<BlobId>, out: &mut Vec<super::Action>) -> Result<bool> {
        let missing = |s: &Self, b: &BlobId| s.conns.get(&conn).is_some_and(|c| c.req.missing.contains(b));
        let ids: Vec<BlobId> = ids.into_iter().filter(|b| !missing(self, b) && !self.asked_for(l, b) && self.state.is_present(&host, &l, b) && !self.memory_skips(&l, b)).collect();
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
    /// (`None`) while an entry of the label that opens under a held secret is asked (`fetching`,
    /// `asked`; it may be a snapshot). Other pending commits settle nothing there, nor do
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



