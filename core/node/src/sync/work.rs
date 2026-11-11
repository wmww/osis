//! Pass work sets (spec/sync.md §6, §7; spec/requirements.md, Scale): what a pass at one host,
//! or a local pass of a label served with no host (`SyncEngine::local_work`), judges again. A verdict on a commit's bodies and entries changes only through a trigger:
//! its entries or their presence or certificate records changed (`State::touch`),
//! the engine marked it changed (`Engine::take_changed`: applied, late parts, a drop, a fired
//! timer, its thing's creation record, its validity flipped, it may have been replaced), a snapshot or a
//! newer card write of its aspects changed under the label, its thing entered or left the
//! closure, a time bound passed (keep at least, expiry; a local pass: an entry's prefix expiry), the state of an aspect its verdict
//! waits on changed (liveness), a role it reads changed (`roles_moved`), or it was
//! judged while unsettled and that ended. Anything else (open, a role or record chain of the label's
//! actor moving, its own secrets, lost access, a forget, other inputs of the pass: keys and epochs, the
//! home label's published things) judges everything. A commit or blob leaves the set only once its pass did
//! nothing for it and found nothing waiting (no send, delete or relay wait outstanding); so a
//! pass over the set acts as a full pass would.

use super::pass::{is_card, is_snapshot};
use super::state::{Kind, Touch};
use super::{ConnId, SyncEngine};
use crate::error::Result;
use crate::labeling::{Body, BodyCtx, HeadKeys};
use osis_base::{Ak, BlobId, CommitId, LabelId, Tid};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Whether closures `a` and `b` are the same: one `Arc` while unchanged (`Groups::closures`;
/// a group containing nothing gets a new one each time).
pub(crate) fn same_closure(a: &Arc<BTreeSet<Tid>>, b: &Arc<BTreeSet<Tid>>) -> bool {
    Arc::ptr_eq(a, b) || a.len() <= 1 && a == b
}

/// Changes for every label (`SyncEngine::engine_events`, `spread_touches`).
#[derive(Clone, Default)]
pub(crate) struct Touched {
    pub full: bool,
    /// The engine's changed commits (`Engine::take_changed`) and this node's own drops.
    pub commits: BTreeSet<CommitId>,
    /// The aspects of changed commits: the commits waiting on their state.
    pub states: BTreeSet<(Tid, Ak)>,
    /// Blobs that arrived or came with a changed commit (a body linking them uploads them now).
    pub blobs: BTreeSet<BlobId>,
    /// Things whose record chains changed (`Held::below` of new record links), or those `roles` reach.
    pub moved: BTreeSet<Tid>,
    /// Whose roles changed and where.
    pub roles: RoleMoves,
    /// Actors that got or lost secrets of their own (the reader actors under them).
    pub actors: BTreeSet<Tid>,
    /// Held epochs may have changed (delete keys a waiting delete lacked).
    pub keys: bool,
    /// A changed edge with an `until`, or a role write ahead of the clock: the roster's clock
    /// horizon may be nearer (`Work::until`).
    pub clock: bool,
}

/// The inbox blobs whose copy a home label's pass found all there (`inbox_certificates`), so
/// passes do not walk them again: a person's grants of 90 days per pass. Dropped when a thing that
/// moves the answer changes, when an entry or a host's copy goes, and by a pass that judges all.
#[derive(Clone, Default)]
pub(crate) struct InboxCopied {
    blobs: BTreeMap<(LabelId, BlobId), BTreeSet<Tid>>,
    by_thing: BTreeSet<(Tid, LabelId, BlobId)>,
    losses: u64,
}

impl InboxCopied {
    pub fn has(&self, l: &LabelId, b: &BlobId) -> bool {
        self.blobs.contains_key(&(*l, *b))
    }

    pub fn add(&mut self, l: LabelId, b: BlobId, on: BTreeSet<Tid>) {
        self.by_thing.extend(on.iter().map(|t| (*t, l, b)));
        self.blobs.insert((l, b), on);
    }

    fn remove(&mut self, l: LabelId, b: BlobId) {
        for t in self.blobs.remove(&(l, b)).into_iter().flatten() {
            self.by_thing.remove(&(t, l, b));
        }
    }

    /// `t`'s roles, record or labels moved.
    pub fn moved(&mut self, t: &Tid) {
        let hit: Vec<(LabelId, BlobId)> = self.by_thing.range((*t, LabelId([0; 16]), BlobId([0; 32]))..=(*t, LabelId([0xff; 16]), BlobId([0xff; 32]))).map(|x| (x.1, x.2)).collect();
        for (l, b) in hit {
            self.remove(l, b);
        }
    }

    /// The sync state's count of entries and copies gone (`State::losses`).
    pub fn lost(&mut self, losses: u64) {
        if self.losses != losses {
            self.losses = losses;
            self.blobs.clear();
            self.by_thing.clear();
        }
    }

    pub fn forget_label(&mut self, l: &LabelId) {
        let hit: Vec<(LabelId, BlobId)> = self.blobs.keys().filter(|(x, _)| x == l).copied().collect();
        for (x, b) in hit {
            self.remove(x, b);
        }
    }
}

impl Touched {
    pub fn is_empty(&self) -> bool {
        !self.full && !self.keys && !self.clock && self.commits.is_empty() && self.states.is_empty() && self.blobs.is_empty() && self.moved.is_empty() && self.roles.is_empty() && self.actors.is_empty()
    }

    /// One entry or commit judged again.
    pub fn add(&mut self, x: Touch) {
        match x {
            Touch::Commit(c) => self.commits.insert(c),
            Touch::Blob(b) => self.blobs.insert(b),
        };
    }

    /// Takes in what `o` collected.
    pub fn absorb(&mut self, o: &Touched) {
        self.full |= o.full;
        self.commits.extend(o.commits.iter().copied());
        self.states.extend(o.states.iter().cloned());
        self.blobs.extend(o.blobs.iter().copied());
        self.moved.extend(o.moved.iter().copied());
        self.roles.merge(&o.roles);
        self.actors.extend(o.actors.iter().copied());
        self.keys |= o.keys;
        self.clock |= o.clock;
    }

    /// What it holds that grows with changes (`SyncConfig::work_max`).
    pub fn size(&self) -> usize {
        self.commits.len() + self.blobs.len() + self.states.len() + self.moved.len() + self.roles.reached.len() + self.roles.subjects.len()
    }
}

/// A change of edges or record links: only `subjects` (`Held::upstream` of the changed edges'
/// holders, and of the things with a new record) gain or lose a role, and only on `reached`
/// (`Held::reach` of the targets and those things). A pass's verdicts read roles as the label's
/// actor, its group or this node, and for another node's card as its author: whom a departure
/// makes stale, and a departure brings a rotation, which judges everything (`Inputs`).
#[derive(Clone, Default)]
pub(crate) struct RoleMoves {
    pub subjects: BTreeSet<Tid>,
    pub reached: BTreeSet<Tid>,
}

impl RoleMoves {
    pub fn is_empty(&self) -> bool {
        self.subjects.is_empty() && self.reached.is_empty()
    }

    pub fn merge(&mut self, o: &RoleMoves) {
        self.subjects.extend(o.subjects.iter().copied());
        self.reached.extend(o.reached.iter().copied());
    }
}

/// What the pass's verdicts depend on beyond single commits: a change judges everything.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Inputs {
    pub head: Option<osis_label::StepId>,
    pub epochs: [Option<osis_crypto::Epoch>; 3],
    pub roles: (bool, bool, bool, bool, bool),
    pub replaced: bool,
    pub actor: Tid,
    pub published: Arc<BTreeSet<Tid>>,
    pub may_rotate: bool,
    /// The group's held epochs (wraps, unopened entries, rotation exceptions).
    pub held: Option<osis_keys::ActorEpochs>,
}

impl Inputs {
    pub fn roles(keys: &HeadKeys, read_ok: bool) -> (bool, bool, bool, bool, bool) {
        (keys.write.is_some(), keys.delete.is_some(), keys.deposit.is_some(), keys.sync_established, read_ok)
    }
}

/// What verdicts wait on: a time, an aspect's state, a linked blob, a key, settling. Filled by a
/// pass (`Left`), kept by the set until the wait ends or a pass judges everything.
#[derive(Clone, Default)]
pub(crate) struct Waits {
    /// Entries and commits whose verdict changes at a time (wall ms).
    pub due: BTreeMap<u64, BTreeSet<Touch>>,
    /// Commits whose verdict waits on an aspect's state (liveness).
    pub aspects: BTreeMap<(Tid, Ak), BTreeSet<CommitId>>,
    /// Blobs a body links that this node neither holds nor has an entry of: the commits that
    /// upload them once they arrive.
    pub links: BTreeMap<BlobId, BTreeSet<CommitId>>,
    /// Commits whose delete waits for a delete key this node lacks: judged again when held
    /// epochs may have changed.
    pub keyless: BTreeSet<CommitId>,
    /// Commits judged while nothing could be deleted (something unsettled) or nothing
    /// established uncovered (an entry being fetched): judged again once that ends.
    pub held_back: BTreeSet<CommitId>,
}

impl Waits {
    fn absorb(&mut self, o: Waits) {
        for (t, xs) in o.due {
            self.due.entry(t).or_default().extend(xs);
        }
        for (k, cs) in o.aspects {
            self.aspects.entry(k).or_default().extend(cs);
        }
        for (b, cs) in o.links {
            self.links.entry(b).or_default().extend(cs);
        }
        self.keyless.extend(o.keyless);
        self.held_back.extend(o.held_back);
    }
}

/// One label's work set at one connection's host (`LConn::work`).
#[derive(Clone, Default)]
pub(crate) struct Work {
    /// What changed: judged by the next pass.
    pub touched: Touched,
    /// Changes from elsewhere since the last pass (`bound`).
    pub elsewhere: usize,
    pub waits: Waits,
    /// At the last pass: whether something was unsettled, and an entry being fetched.
    pub withheld: (bool, bool),
    pub inputs: Option<Inputs>,
    /// When the clock alone next changes a role the verdicts read (an edge's `until`, a
    /// role write ahead of the clock): everything is judged then.
    pub until: Option<u64>,
    /// Aggregates over the label's entries, kept by the touches (rebuilt by a full pass).
    pub closure: Arc<BTreeSet<Tid>>,
    pub unsettled: BTreeSet<Option<(Tid, Ak)>>,
    pub snaps: BTreeMap<(Tid, Ak), BTreeSet<(BlobId, CommitId)>>,
    /// Entries that unwrap under a held read secret and are not opened.
    pub unopened: BTreeSet<BlobId>,
    /// Commit entries judged invalid or not judged yet, with their authors.
    pub unjudged: BTreeMap<CommitId, Tid>,
    /// Other nodes' card commits under the label (`stale_card` reads their author's roster).
    pub cards: BTreeSet<CommitId>,
    /// The last pass left something only another pass finds out about (`Left`), or the label's
    /// own records were touched or a wait woken since: passes at its next resync.
    pub again: bool,
    /// When time alone next wants a pass (wall ms, as the due times it comes from;
    /// `SyncEngine::schedule_pass`): `Some(0)` at the next resync, none never.
    pub pass_at: Option<u64>,
    /// When `pass_at` was set (wall ms): a clock now before it went back.
    pub scheduled: u64,
}

impl Work {
    /// A set that judges everything at its first pass (a label opened, a local pass begun).
    pub fn fresh() -> Work {
        Work { touched: Touched { full: true, ..Touched::default() }, ..Work::default() }
    }

    /// Whether no pass is wanted but at `pass_at`: nothing left, nothing touched, nothing
    /// unsettled or unopened. A change from elsewhere waiting here (`spread_touches`) is no
    /// reason: the label's marks would have passed it if it concerned the label.
    pub fn quiet(&self) -> bool {
        !self.touched.full && !self.again && self.unopened.is_empty() && self.waits.held_back.is_empty() && self.unsettled.is_empty()
    }

    /// Whether a resync at `now` (wall ms) passes this label: also once when the clock
    /// went back since `pass_at` was set (it was set at a later time).
    pub fn resync_due(&self, now: u64) -> bool {
        !self.quiet() || self.pass_at.is_some_and(|t| t <= now) || now < self.scheduled
    }

    /// Whether changes `t` wake a verdict waiting here (`prepare`): the next resync judges it.
    pub fn woken_by(&self, t: &Touched) -> bool {
        let w = &self.waits;
        t.states.iter().any(|k| w.aspects.contains_key(k)) || t.blobs.iter().any(|b| w.links.contains_key(b)) || t.keys && !w.keyless.is_empty()
    }

    /// Takes in what another set collected meanwhile (a pass's own touches).
    pub fn merge(&mut self, o: Work) {
        self.again |= o.again;
        self.touched.absorb(&o.touched);
        self.elsewhere = self.elsewhere.saturating_add(o.elsewhere);
    }

    /// Notes `n` more changes from elsewhere. Past `max` since the last pass, the next pass judges
    /// everything instead (`SyncConfig::work_max`). What the pass left and the label's own touches
    /// do not count: at most what the label holds, and uploads a host has yet to take would make
    /// every pass full.
    pub fn bound(&mut self, n: usize, max: usize) {
        self.elsewhere = self.elsewhere.saturating_add(n);
        if self.elsewhere > max {
            self.touched = Touched { full: true, ..Touched::default() };
        }
    }

    /// Takes what pass left to do (`Left`) as the next pass's set.
    pub fn leave(&mut self, left: Left) {
        self.touched.full = false;
        self.again = left.again || !left.commits.is_empty() || !left.blobs.is_empty();
        self.touched.commits = left.commits;
        self.touched.blobs = left.blobs;
        self.elsewhere = 0;
        self.waits.absorb(left.waits);
    }
}

/// What a pass judges: everything, or these commits and blobs.
pub(crate) enum Scope {
    All,
    Some { commits: BTreeSet<CommitId>, blobs: BTreeSet<BlobId> },
}

impl Scope {
    pub fn is_all(&self) -> bool {
        matches!(self, Scope::All)
    }

    pub fn has(&self, c: &CommitId) -> bool {
        match self {
            Scope::All => true,
            Scope::Some { commits, .. } => commits.contains(c),
        }
    }
}

/// What a pass left to do: judged again next pass, or on what it waits for.
#[derive(Default)]
pub(crate) struct Left {
    pub commits: BTreeSet<CommitId>,
    pub blobs: BTreeSet<BlobId>,
    pub waits: Waits,
    /// Something outside the set waits for a later pass: a relay the host lacks, a deposit not
    /// promoted.
    pub again: bool,
}

impl Left {
    pub fn at(&mut self, t: u64, x: Touch) {
        self.waits.due.entry(t).or_default().insert(x);
    }

    pub fn wait(&mut self, t: Tid, a: Ak, c: CommitId) {
        self.waits.aspects.entry((t, a)).or_default().insert(c);
    }

    /// Commit `c` waits for linked blob `b`.
    pub fn link(&mut self, b: BlobId, c: CommitId) {
        self.waits.links.entry(b).or_default().insert(c);
    }
}

/// Notes a judgment makes for the work set (`Left`): its answer may change without a trigger
/// (`unsure`), at a time, or with an aspect's state.
#[derive(Default)]
pub(crate) struct Note {
    pub unsure: bool,
    pub at: Option<u64>,
    pub waits: Vec<(Tid, Ak)>,
    /// A delete waits for a key this node may get with new epochs.
    pub keyless: bool,
}

impl Note {
    pub fn at(&mut self, t: u64) {
        self.at = Some(self.at.map_or(t, |x| x.min(t)));
    }

    /// Moves the note into `left` for commit `c`.
    pub fn leave(&mut self, c: CommitId, left: &mut Left) {
        if std::mem::take(&mut self.unsure) {
            left.commits.insert(c);
        }
        if let Some(t) = self.at.take() {
            left.at(t, Touch::Commit(c));
        }
        for (t, a) in std::mem::take(&mut self.waits) {
            left.wait(t, a, c);
        }
        if std::mem::take(&mut self.keyless) {
            left.waits.keyless.insert(c);
        }
    }
}

impl SyncEngine {
    /// Readies work set `w` of label `l` of `g` for a pass: due times and waited-on aspect
    /// states move their commits in, touched aspects, things and the closure's changes expand
    /// to their commits, the aggregates follow. Returns whether the pass judges everything.
    pub(super) fn prepare(&mut self, g: &Tid, l: &LabelId, w: &mut Work, closure: &Arc<BTreeSet<Tid>>) -> bool {
        let now = self.now();
        let later = w.waits.due.split_off(&now.saturating_add(1));
        for x in std::mem::replace(&mut w.waits.due, later).into_values().flatten() {
            w.touched.add(x);
        }
        for k in std::mem::take(&mut w.touched.states) {
            if let Some(cs) = w.waits.aspects.remove(&k) {
                w.touched.commits.extend(cs);
            }
        }
        for b in &w.touched.blobs {
            if let Some(cs) = w.waits.links.remove(b) {
                w.touched.commits.extend(cs);
            }
        }
        w.touched.commits.extend(self.commits_of(l, &w.touched.blobs));
        let x = self.engine.group_actor(g);
        // roles the pass reads as the actor, the group or this node
        let RoleMoves { subjects, reached } = std::mem::take(&mut w.touched.roles);
        if subjects.contains(&x) || subjects.contains(g) || subjects.contains(&self.engine.tid()) || self.engine.account_tid().is_some_and(|a| subjects.contains(&a)) {
            w.touched.moved.extend(reached);
        }
        // a change of the record chain or of a role of the label's own actor (every entry's
        // reader may stand anew), or of whether it has secrets of its own
        let own = w.touched.moved.contains(&x) || w.touched.actors.contains(&x);
        let full = w.touched.full || own || self.cfg.full_passes || w.until.is_some_and(|u| u <= now);
        if full {
            self.go_full(g, l, w, closure);
        } else {
            let mut things = self.roles_moved(g, l, w, closure);
            if std::mem::take(&mut w.touched.clock) {
                w.until = self.roster_horizon(closure, g);
            }
            // an unchanged closure is the same `Arc` (`Groups::closures`)
            if !same_closure(closure, &w.closure) {
                things.extend(closure.symmetric_difference(&w.closure).copied());
            }
            // a snapshot changes coverage of its aspects; a node's newer card write makes its
            // older card stale (spec/permissions.md §4)
            let me = self.engine.tid();
            let mut aspects: BTreeSet<(Tid, Ak)> = BTreeSet::new();
            let mut older: BTreeSet<CommitId> = BTreeSet::new();
            let mut own: BTreeMap<(Tid, Ak, Tid), Vec<CommitId>> = BTreeMap::new();
            for c in &w.touched.commits {
                let Some(h) = self.engine.header(c) else { continue };
                let snapshot = is_snapshot(h.kind);
                for a in &h.aspects {
                    let card = a.tid == h.author && h.author != me && is_card(a.ak.as_str());
                    if snapshot || card {
                        aspects.insert((a.tid, a.ak.clone()));
                    }
                    if !snapshot && self.engine.own_replace(c, &a.tid, &a.ak) {
                        own.entry((a.tid, a.ak.clone(), h.author)).or_default().push(*c);
                        // a carrier for what a delete waits on (spec/sync.md §7)
                        if let Some(cs) = w.waits.aspects.remove(&(a.tid, a.ak.clone())) {
                            older.extend(cs);
                        }
                    }
                }
            }
            // a snapshot changes nothing for a body read on its own: only the aspect's cover
            // candidates are judged (`Core::cover_judged_on`), so its arrival costs O(change)
            // what waits on the aspect (a delete waiting for a carrier) is judged again
            for k in aspects {
                if is_card(k.1.as_str()) {
                    w.touched.commits.extend(self.engine.core.held_on(&k));
                } else {
                    w.touched.commits.extend(self.engine.core.cover_judged_on(&k));
                    if let Some(cs) = w.waits.aspects.remove(&k) {
                        w.touched.commits.extend(cs);
                    }
                }
            }
            // what own replaces let go, judged together: several may arrive or turn valid at once
            for ((t, a, _), qs) in own {
                older.extend(self.engine.own_newly_covered(&qs, &t, &a));
            }
            w.touched.commits.extend(older);
            for t in things {
                w.touched.commits.extend(self.commits_on_thing(&t));
            }
            let (cs, bs) = (w.touched.commits.clone(), w.touched.blobs.clone());
            self.aggregate(g, l, w, &cs, &bs);
        }
        w.closure = closure.clone();
        full
    }

    /// What role changes that leave the actor of `g` alone move under its label `l`
    /// (spec/sync.md §3 entitlement, §6, §7; spec/permissions.md §4): the things of the closure,
    /// and of the `label.0`s its home label publishes, whose roles changed (`Held::reach` of the
    /// changed rosters and record links) or whose record chain holds an actor that got or lost
    /// secrets of its own (reader actors); the label's own commits with a delta on such a thing
    /// (a superset's foreign deltas); other nodes' cards (their author's departure); deletes
    /// waiting for a key. A label they reach takes its roster horizon again. Returns those things.
    fn roles_moved(&mut self, g: &Tid, l: &LabelId, w: &mut Work, closure: &BTreeSet<Tid>) -> BTreeSet<Tid> {
        if std::mem::take(&mut w.touched.keys) {
            w.touched.commits.extend(std::mem::take(&mut w.waits.keyless));
        }
        let moved = std::mem::take(&mut w.touched.moved);
        let actors = std::mem::take(&mut w.touched.actors);
        let mut things = BTreeSet::new();
        if moved.is_empty() && actors.is_empty() {
            return things;
        }
        let published = self.engine.published_under(g);
        let engine = &self.engine;
        let under = |t: &Tid| engine.record_chain(t).any(|c| actors.contains(&c));
        let mut hit = false;
        for t in closure.iter().chain(published.iter()) {
            if moved.contains(t) || !actors.is_empty() && under(t) {
                things.insert(*t);
                hit = true;
            }
        }
        // the label's own commits once: an entry's foreign deltas read their reader actors
        let mut seen: BTreeMap<Tid, bool> = BTreeMap::new();
        let cs: Vec<CommitId> = self.state.label_commits(l).collect();
        for c in cs {
            let Some(h) = self.engine.header(&c) else { continue };
            let found = h.aspects.iter().any(|a| moved.contains(&a.tid) || !actors.is_empty() && *seen.entry(a.tid).or_insert_with(|| under(&a.tid)));
            if found {
                w.touched.commits.insert(c);
                hit = true;
            }
        }
        if !moved.is_empty() {
            w.touched.commits.extend(w.cards.iter().copied());
        }
        if hit {
            w.until = self.roster_horizon(closure, g);
        }
        things
    }

    /// The commits of the entries among `bs` under `l` (a blob touched before it opened).
    fn commits_of(&self, l: &LabelId, bs: &BTreeSet<BlobId>) -> Vec<CommitId> {
        bs.iter().filter_map(|b| match self.state.entries.get(&(*l, *b)).map(|e| &e.kind) {
            Some(Kind::Commit { commit, .. }) => Some(*commit),
            _ => None,
        }).collect()
    }

    /// The next time the clock alone changes a roster that entitlement and departures under a
    /// label of `g` read (`rotation::departures::direct_departures` has the same horizon per actor): the
    /// components of its actor and of its closure's reader actors.
    fn roster_horizon(&self, closure: &BTreeSet<Tid>, g: &Tid) -> Option<u64> {
        let core = &self.engine.core;
        self.horizon(closure.iter().chain([g]).map(|t| core.reader_of(t)).collect::<BTreeSet<Tid>>().into_iter())
    }

    /// The first time after now that a grant's `until` or a role commit's `ts` falls due in the
    /// components of `actors` (wall ms).
    pub(super) fn horizon(&self, actors: impl Iterator<Item = Tid>) -> Option<u64> {
        let now = self.now();
        let core = &self.engine.core;
        let mut seen: Vec<*const osis_perm::Timeline> = Vec::new();
        let mut out: Option<u64> = None;
        let mut later = |t: u64| {
            if t > now {
                out = Some(out.map_or(t, |x| x.min(t)));
            }
        };
        for t in actors {
            let Some(tl) = core.timelines.get(&t) else { continue };
            if seen.contains(&std::ptr::from_ref(tl)) {
                continue;
            }
            seen.push(std::ptr::from_ref(tl));
            for (_, _, e) in tl.edges_at(None).iter() {
                if let Some(u) = e.until {
                    later(u.0);
                }
            }
            for wid in tl.applied().keys() {
                if let Some(ts) = tl.role_commit(&wid.0).map(|m| m.ts) {
                    later(ts.wall_ms().0);
                }
            }
        }
        out
    }

    /// Readies `w` for a pass judging everything: what it named and waited on goes, the
    /// aggregates and the roster horizon are taken anew.
    pub(super) fn go_full(&mut self, g: &Tid, l: &LabelId, w: &mut Work, closure: &BTreeSet<Tid>) {
        self.inbox_copied.forget_label(l);
        // `full` stands until the pass ends well (`leave`)
        w.touched = Touched { full: w.touched.full, ..Touched::default() };
        w.waits = Waits::default();
        self.rebuild(g, l, w);
        w.until = self.roster_horizon(closure, g);
    }

    /// Every held commit with a delta on thing `t`.
    fn commits_on_thing(&self, t: &Tid) -> BTreeSet<CommitId> {
        self.engine.core.aspects_of(t).flat_map(|(_, s)| s.iter().map(|x| x.1)).collect()
    }

    /// The aggregates of `w` from every entry under `l`.
    pub(super) fn rebuild(&mut self, g: &Tid, l: &LabelId, w: &mut Work) {
        w.snaps.clear();
        w.unopened.clear();
        w.unjudged.clear();
        w.cards.clear();
        let cs: BTreeSet<CommitId> = self.state.label_commits(l).collect();
        let bs: BTreeSet<BlobId> = self.state.of_kind(l, Kind::TAG_UNKNOWN).into_iter().collect();
        self.aggregate(g, l, w, &cs, &bs);
    }

    /// Brings the aggregates of `w` up to date for commits `cs` and blobs `bs`.
    fn aggregate(&mut self, g: &Tid, l: &LabelId, w: &mut Work, cs: &BTreeSet<CommitId>, bs: &BTreeSet<BlobId>) {
        // cards are written by the node itself
        let me = self.engine.tid();
        for c in cs {
            let entries: Vec<Vec<usize>> = self.state.entries_of(l, c).filter_map(|(_, e)| if let Kind::Commit { parts, .. } = &e.kind { Some(parts.clone()) } else { None }).collect();
            let blobs: Vec<BlobId> = self.state.entries_of(l, c).map(|(b, _)| b).collect();
            let Some(h) = self.engine.header(c) else {
                w.unjudged.remove(c);
                continue;
            };
            for a in &h.aspects {
                let k = (a.tid, a.ak.clone());
                if is_snapshot(h.kind) || self.engine.own_replace(c, &a.tid, &a.ak) {
                    let set = w.snaps.entry(k.clone()).or_default();
                    set.retain(|(_, x)| x != c);
                    set.extend(blobs.iter().map(|b| (*b, *c)));
                } else if let Some(set) = w.snaps.get_mut(&k) {
                    set.retain(|(_, x)| x != c);
                }
                if w.snaps.get(&k).is_some_and(|set| set.is_empty()) {
                    w.snaps.remove(&k);
                }
            }
            if entries.iter().any(|p| !self.engine.judged_valid(c, p)) {
                w.unjudged.insert(*c, h.author);
            } else {
                w.unjudged.remove(c);
            }
            if h.author != me && !blobs.is_empty() && h.aspects.iter().any(|x| x.tid == h.author && is_card(x.ak.as_str())) {
                w.cards.insert(*c);
            } else {
                w.cards.remove(c);
            }
        }
        if bs.is_empty() {
            return;
        }
        let secrets = self.read_secrets(g);
        for b in bs {
            // a shredded one is a dropped body's, missing again: the fetch brings its wrap
            if self.state.entries.get(&(*l, *b)).is_some_and(|e| e.unopened(b, &secrets)) {
                w.unopened.insert(*b);
            } else {
                w.unopened.remove(b);
            }
        }
    }

    /// Takes in what changed during this pass so far (entries opened, copies placed): judged
    /// in the rest of the pass, and again by the next.
    /// `conn` `None`: the label's local pass (`SyncEngine::local_work`).
    pub(super) fn pull(&mut self, conn: Option<ConnId>, g: &Tid, l: LabelId, scope: &mut Scope, w: &mut Work) {
        self.spread_touches();
        let meanwhile = match conn {
            Some(conn) => self.lc(conn, &l).map(|lc| &lc.work),
            None => self.local_work.get(&l),
        };
        let Some((mut cs, bs)) = meanwhile.map(|w| (w.touched.commits.clone(), w.touched.blobs.clone())) else { return };
        cs.extend(self.commits_of(&l, &bs));
        self.aggregate(g, &l, w, &cs, &bs);
        if let Scope::Some { commits, blobs } = scope {
            commits.extend(cs);
            blobs.extend(bs);
        }
    }

    /// The certificate copies this node placed under `l` in `scope`, by blob.
    pub(super) fn cert_entries(&self, l: &LabelId, scope: &Scope) -> BTreeSet<BlobId> {
        match scope {
            Scope::All => self.state.cert_entries.range((*l, BlobId([0; 32]))..=(*l, BlobId([0xff; 32]))).map(|(_, b)| *b).collect(),
            Scope::Some { commits, blobs } => {
                let mut out: BTreeSet<BlobId> = commits.iter().flat_map(|c| self.state.entries_of(l, c).filter(|(_, e)| e.cert).map(|(b, _)| b)).collect();
                out.extend(blobs.iter().filter(|b| self.state.cert_entries.contains(&(*l, **b))));
                out
            }
        }
    }

    /// The bodies label `l` of `g` should hold among the commits of `scope`
    /// (`bodies_under`).
    pub(super) fn bodies_in(&mut self, ctx: &BodyCtx, g: &Tid, l: &LabelId, scope: &Scope) -> Result<Vec<Body>> {
        let Scope::Some { commits, .. } = scope else { return self.bodies_under(g, l) };
        let replaced = self.is_replaced(g, l);
        let mut out = Vec::new();
        for c in commits {
            let mut bs = self.engine.commit_bodies_under(ctx, c)?;
            if replaced {
                bs.retain(|b| b.role_commit);
            }
            out.extend(bs);
        }
        Ok(out)
    }
}
