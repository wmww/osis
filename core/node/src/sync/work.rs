//! Pass work sets (spec/sync.md §6, §7; spec/requirements.md, Scale): what a pass at one server,
//! or a local pass of a label served with no server (`SyncEngine::local_work`), judges again. A verdict on a commit's bodies and entries changes only through a trigger:
//! its entries or their presence, certificate or timed-delete records changed (`State::touch`),
//! the engine marked it changed (`Engine::take_changed`: applied, late parts, a drop, a fired
//! timer, its thing's creation record, its validity flipped, its deaths moved), a snapshot or a
//! newer card write of its aspects changed under the label, its thing entered or left the
//! closure, a time bound passed (keep at least, expiry; a local pass: an entry's prefix expiry), the state of an aspect its verdict
//! waits on changed (liveness; a keep-at-most body: other than by a valid write's join), a role it reads changed (`membership_moved`), or it was
//! judged while unsettled and that ended. Anything else (open, a change of the label actor's
//! roster or own secrets, lost access, a forget, other inputs of the pass: keys and epochs, the
//! home label's published things) judges everything. A commit or blob leaves the set only once its pass did
//! nothing for it and found nothing waiting (no send, delete or relay wait outstanding); so a
//! pass over the set acts as a full pass would.

use super::pass::{is_card, is_snapshot};
use super::state::Kind;
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
#[derive(Default)]
pub(crate) struct Touched {
    pub full: bool,
    /// The engine's changed commits (`Engine::take_changed`) and this node's own drops.
    pub commits: BTreeSet<CommitId>,
    /// The aspects of changed commits: the commits waiting on their state.
    pub states: BTreeSet<(Tid, Ak)>,
    /// Aspects whose state changed other than by valid writes (`engine::Changed::aspects`).
    pub whole: BTreeSet<(Tid, Ak)>,
    /// Blobs that arrived or came with a changed commit (a body linking them uploads them now).
    pub blobs: BTreeSet<BlobId>,
    /// Things whose roles changed (`Held::reach` of changed rosters and owner links).
    pub moved: BTreeSet<Tid>,
    /// Actors that got or lost secrets of their own (the reader actors under them).
    pub actors: BTreeSet<Tid>,
    /// Held epochs may have changed (delete keys a waiting delete lacked).
    pub keys: bool,
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

/// One label's work set at one connection's server (`LConn::work`).
#[derive(Default)]
pub(crate) struct Work {
    /// Judge everything next pass.
    pub full: bool,
    pub commits: BTreeSet<CommitId>,
    pub blobs: BTreeSet<BlobId>,
    pub aspects: BTreeSet<(Tid, Ak)>,
    pub states: BTreeSet<(Tid, Ak)>,
    pub whole: BTreeSet<(Tid, Ak)>,
    pub things: BTreeSet<Tid>,
    pub moved: BTreeSet<Tid>,
    pub actors: BTreeSet<Tid>,
    pub keys: bool,
    /// Commits whose delete waits for a delete key this node lacks: judged again when held
    /// epochs may have changed.
    pub keyless: BTreeSet<CommitId>,
    /// Commits judged while nothing could be deleted (something unsettled) or nothing
    /// established uncovered (an entry being fetched): judged again once that ends.
    pub held_back: BTreeSet<CommitId>,
    /// At the last pass: whether nothing was unsettled, and no entry was being fetched.
    pub settled: Option<(bool, bool)>,
    /// Commits whose verdict changes at a time (raw-free corrected wall ms).
    pub due: BTreeMap<u64, BTreeSet<CommitId>>,
    /// Other entries whose verdict changes at a time (a local pass: a prefix's expiry).
    pub due_blobs: BTreeMap<u64, BTreeSet<BlobId>>,
    /// Commits whose verdict waits on an aspect's state (liveness).
    pub waits: BTreeMap<(Tid, Ak), BTreeSet<CommitId>>,
    /// Keep-at-most bodies before their timed delete: a valid write changes their bound or
    /// liveness only by killing their writes, which marks them (`retention::note_deaths`,
    /// replays), so only the aspect's other state changes (`whole`) wake them.
    pub at_most: BTreeMap<(Tid, Ak), BTreeSet<CommitId>>,
    /// Blobs a body links that this node neither holds nor has an entry of: the commits that
    /// upload them once they arrive.
    pub links: BTreeMap<BlobId, BTreeSet<CommitId>>,
    pub inputs: Option<Inputs>,
    /// When the clock alone next changes a role the verdicts read (an edge's `until`, a
    /// membership write ahead of the clock): everything is judged then.
    pub until: Option<u64>,
    /// Aggregates over the label's entries, kept by the touches (rebuilt by a full pass).
    pub closure: Arc<BTreeSet<Tid>>,
    pub unsettled: BTreeSet<Option<(Tid, Ak)>>,
    pub snaps: BTreeMap<(Tid, Ak), BTreeSet<(BlobId, CommitId)>>,
    /// Entries that unwrap under a held read secret and are not opened.
    pub unopened: BTreeSet<BlobId>,
    /// Commit entries judged invalid or not judged yet, with their authors.
    pub unjudged: BTreeMap<CommitId, Tid>,
    /// Other nodes' heartbeats under the label.
    pub beats: BTreeMap<Tid, BTreeSet<(osis_base::Ts, CommitId)>>,
    /// Other nodes' card commits under the label (`stale_card` reads their author's roster).
    pub cards: BTreeSet<CommitId>,
}

impl Work {
    /// A set that judges everything at its first pass (a label opened, a local pass begun).
    pub fn fresh() -> Work {
        Work { full: true, ..Work::default() }
    }

    /// Takes in what another set collected meanwhile (a pass's own touches).
    pub fn merge(&mut self, o: Work) {
        self.full |= o.full;
        self.commits.extend(o.commits);
        self.blobs.extend(o.blobs);
        self.aspects.extend(o.aspects);
        self.states.extend(o.states);
        self.whole.extend(o.whole);
        self.things.extend(o.things);
        self.moved.extend(o.moved);
        self.actors.extend(o.actors);
        self.keys |= o.keys;
    }

    /// Takes what pass left to do (`Left`) as the next pass's set.
    pub fn leave(&mut self, left: Left) {
        self.full = false;
        self.commits = left.commits;
        self.blobs = left.blobs;
        for (t, cs) in left.due {
            self.due.entry(t).or_default().extend(cs);
        }
        for (t, bs) in left.due_blobs {
            self.due_blobs.entry(t).or_default().extend(bs);
        }
        for (k, cs) in left.waits {
            self.waits.entry(k).or_default().extend(cs);
        }
        for (k, cs) in left.at_most {
            self.at_most.entry(k).or_default().extend(cs);
        }
        for (b, cs) in left.links {
            self.links.entry(b).or_default().extend(cs);
        }
        self.keyless.extend(left.keyless);
        self.held_back.extend(left.held_back);
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

/// What a pass left to do: judged again next pass, at a time, or when an aspect's state
/// changes.
#[derive(Default)]
pub(crate) struct Left {
    pub commits: BTreeSet<CommitId>,
    pub blobs: BTreeSet<BlobId>,
    pub due: BTreeMap<u64, BTreeSet<CommitId>>,
    pub due_blobs: BTreeMap<u64, BTreeSet<BlobId>>,
    pub waits: BTreeMap<(Tid, Ak), BTreeSet<CommitId>>,
    pub at_most: BTreeMap<(Tid, Ak), BTreeSet<CommitId>>,
    pub links: BTreeMap<BlobId, BTreeSet<CommitId>>,
    pub keyless: BTreeSet<CommitId>,
    pub held_back: BTreeSet<CommitId>,
}

impl Left {
    pub fn at(&mut self, t: u64, c: CommitId) {
        self.due.entry(t).or_default().insert(c);
    }

    pub fn wait(&mut self, t: Tid, a: Ak, c: CommitId) {
        self.waits.entry((t, a)).or_default().insert(c);
    }

    /// Keep-at-most body `c` of `(t, a)` waits for its timed delete (`Work::at_most`).
    pub fn wait_at_most(&mut self, t: Tid, a: Ak, c: CommitId) {
        self.at_most.entry((t, a)).or_default().insert(c);
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
            left.at(t, c);
        }
        for (t, a) in std::mem::take(&mut self.waits) {
            left.wait(t, a, c);
        }
        if std::mem::take(&mut self.keyless) {
            left.keyless.insert(c);
        }
    }
}

impl SyncEngine {
    /// Readies work set `w` of label `l` of `g` for a pass: due times and waited-on aspect
    /// states move their commits in, touched aspects, things and the closure's changes expand
    /// to their commits, the aggregates follow. Returns whether the pass judges everything.
    pub(super) fn prepare(&mut self, g: &Tid, l: &LabelId, w: &mut Work, closure: &Arc<BTreeSet<Tid>>) -> bool {
        let now = self.now();
        let later = w.due.split_off(&now.saturating_add(1));
        for (_, cs) in std::mem::replace(&mut w.due, later) {
            w.commits.extend(cs);
        }
        let later = w.due_blobs.split_off(&now.saturating_add(1));
        for (_, bs) in std::mem::replace(&mut w.due_blobs, later) {
            w.blobs.extend(bs);
        }
        for k in std::mem::take(&mut w.states).into_iter().chain(w.aspects.iter().cloned()) {
            if let Some(cs) = w.waits.remove(&k) {
                w.commits.extend(cs);
            }
        }
        for k in std::mem::take(&mut w.whole).into_iter().chain(w.aspects.iter().cloned()) {
            if let Some(cs) = w.at_most.remove(&k) {
                w.commits.extend(cs);
            }
        }
        for b in &w.blobs {
            if let Some(cs) = w.links.remove(b) {
                w.commits.extend(cs);
            }
        }
        w.commits.extend(self.commits_of(l, &w.blobs));
        // a change of the label's own actor's roster (every entry's author may stand anew on
        // it) or of whether it has secrets of its own
        let x = self.engine.group_actor(g);
        let own = w.moved.contains(&x) || w.actors.contains(&x);
        let full = w.full || own || self.cfg.full_passes || w.until.is_some_and(|u| u <= now);
        if full {
            self.go_full(g, l, w, closure);
        } else {
            self.membership_moved(g, l, w, closure);
            // an unchanged closure is the same `Arc` (`Groups::closures`)
            if !same_closure(closure, &w.closure) {
                w.things.extend(closure.symmetric_difference(&w.closure).copied());
            }
            // a snapshot changes coverage of its aspects; a node's newer card write makes its
            // older card stale (spec/permissions.md §4)
            let me = self.engine.tid();
            for c in &w.commits {
                let Some(h) = self.engine.header(c) else { continue };
                let snapshot = is_snapshot(h.kind);
                for a in &h.aspects {
                    let card = a.tid == h.author && h.author != me && is_card(a.ak.as_str());
                    if snapshot || card {
                        w.aspects.insert((a.tid, a.ak.clone()));
                    }
                }
            }
            for (t, a) in std::mem::take(&mut w.aspects) {
                w.commits.extend(self.engine.core.ix.by_aspect.get(&(t, a)).into_iter().flatten().map(|x| x.1));
            }
            for t in std::mem::take(&mut w.things) {
                w.commits.extend(self.commits_on_thing(&t));
            }
            let (cs, bs) = (w.commits.clone(), w.blobs.clone());
            self.aggregate(g, l, w, &cs, &bs);
        }
        w.closure = closure.clone();
        full
    }

    /// What membership changes that leave the actor of `g` alone move under its label `l`
    /// (spec/sync.md §3 entitlement, §6, §7; spec/permissions.md §4): the things of the closure,
    /// and of the `/label`s its home label publishes, whose roles changed (`Held::reach` of the
    /// changed rosters and owner links) or whose owner chain holds an actor that got or lost
    /// secrets of its own (reader actors); the label's own commits with a delta on such a thing
    /// (a superset's foreign deltas); other nodes' cards (their author's departure); deletes
    /// waiting for a key. A label they reach takes its roster horizon again.
    fn membership_moved(&mut self, g: &Tid, l: &LabelId, w: &mut Work, closure: &BTreeSet<Tid>) {
        if std::mem::take(&mut w.keys) {
            w.commits.extend(std::mem::take(&mut w.keyless));
        }
        let moved = std::mem::take(&mut w.moved);
        let actors = std::mem::take(&mut w.actors);
        if moved.is_empty() && actors.is_empty() {
            return;
        }
        let published = self.engine.published_under(g);
        let engine = &self.engine;
        let under = |t: &Tid| engine.owner_chain(t).any(|c| actors.contains(&c));
        let mut hit = false;
        for t in closure.iter().chain(published.iter()) {
            if moved.contains(t) || !actors.is_empty() && under(t) {
                w.things.insert(*t);
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
                w.commits.insert(c);
                hit = true;
            }
        }
        if !moved.is_empty() {
            w.commits.extend(w.cards.iter().copied());
        }
        if hit {
            w.until = self.roster_horizon(closure, g);
        }
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
        let now = self.now();
        let core = &self.engine.core;
        let mut seen: Vec<*const osis_perm::Timeline> = Vec::new();
        let mut out: Option<u64> = None;
        let mut later = |t: u64| {
            if t > now {
                out = Some(out.map_or(t, |x| x.min(t)));
            }
        };
        for t in closure.iter().chain([g]).map(|t| core.reader_of(t)).collect::<BTreeSet<Tid>>() {
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
                let ts = match wid {
                    osis_perm::WriteId::Op(c, _) => tl.membership_commit(c).map(|m| m.ts),
                    osis_perm::WriteId::Snapshot(c) => tl.roster_snapshot(c).map(|s| s.ts),
                };
                if let Some(ts) = ts {
                    later(ts.wall_ms().0);
                }
            }
        }
        out
    }

    /// Readies `w` for a pass judging everything: what it named and waited on goes, the
    /// aggregates and the roster horizon are taken anew.
    pub(super) fn go_full(&mut self, g: &Tid, l: &LabelId, w: &mut Work, closure: &BTreeSet<Tid>) {
        w.commits.clear();
        w.blobs.clear();
        w.aspects.clear();
        w.things.clear();
        w.waits.clear();
        w.at_most.clear();
        w.whole.clear();
        w.links.clear();
        w.due.clear();
        w.due_blobs.clear();
        w.moved.clear();
        w.actors.clear();
        w.keys = false;
        w.keyless.clear();
        w.held_back.clear();
        self.rebuild(g, l, w);
        w.until = self.roster_horizon(closure, g);
    }

    /// Every commit with a delta on thing `t`.
    fn commits_on_thing(&self, t: &Tid) -> BTreeSet<CommitId> {
        let Ok(min) = Ak::new("/\0") else { return BTreeSet::new() };
        self.engine.core.ix.by_aspect.range((*t, min)..).take_while(|((x, _), _)| x == t).flat_map(|(_, s)| s.iter().map(|x| x.1)).collect()
    }

    /// The aggregates of `w` from every entry under `l`.
    pub(super) fn rebuild(&mut self, g: &Tid, l: &LabelId, w: &mut Work) {
        w.snaps.clear();
        w.unopened.clear();
        w.unjudged.clear();
        w.beats.clear();
        w.cards.clear();
        let cs: BTreeSet<CommitId> = self.state.label_commits(l).collect();
        let bs: BTreeSet<BlobId> = self.state.of_kind(l, 0).into_iter().collect();
        self.aggregate(g, l, w, &cs, &bs);
    }

    /// Brings the aggregates of `w` up to date for commits `cs` and blobs `bs`.
    fn aggregate(&mut self, g: &Tid, l: &LabelId, w: &mut Work, cs: &BTreeSet<CommitId>, bs: &BTreeSet<BlobId>) {
        let me = self.engine.tid();
        for c in cs {
            let entries: Vec<Vec<(usize, usize)>> = self.state.entries_of(l, c).filter_map(|(_, e)| if let Kind::Commit { parts, .. } = &e.kind { Some(parts.clone()) } else { None }).collect();
            let blobs: Vec<BlobId> = self.state.entries_of(l, c).map(|(b, _)| b).collect();
            let Some(h) = self.engine.header(c) else {
                w.unjudged.remove(c);
                continue;
            };
            if is_snapshot(h.kind) {
                for a in &h.aspects {
                    let set = w.snaps.entry((a.tid, a.ak.clone())).or_default();
                    set.retain(|(_, x)| x != c);
                    set.extend(blobs.iter().map(|b| (*b, *c)));
                    if set.is_empty() {
                        w.snaps.remove(&(a.tid, a.ak.clone()));
                    }
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
            if h.author != me && h.aspects.iter().any(|x| x.ak.as_str() == "/seen" && x.tid == h.author) {
                let set = w.beats.entry(h.author).or_default();
                set.retain(|(_, x)| x != c);
                if !blobs.is_empty() {
                    set.insert((h.ts, *c));
                }
                if set.is_empty() {
                    w.beats.remove(&h.author);
                }
            }
        }
        if bs.is_empty() {
            return;
        }
        let secrets = self.read_secrets(g);
        for b in bs {
            // a shredded one is a dropped body's, missing again: the fetch brings its wrap
            let open = self.state.entries.get(&(*l, *b)).is_some_and(|e| e.kind == Kind::Unknown && (e.shredded() || osis_label::unwrap_any(secrets.iter(), b, &e.wrap).is_some()));
            if open {
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
        let Some((mut cs, bs)) = meanwhile.map(|w| (w.commits.clone(), w.blobs.clone())) else { return };
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
                bs.retain(|b| b.membership);
            }
            out.extend(bs);
        }
        Ok(out)
    }
}
