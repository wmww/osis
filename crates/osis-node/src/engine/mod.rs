//! The engine: one node's local state over its `Store` (notes/architecture.md §2: the node
//! talks to `Store` only). Synchronous, no I/O of its own, time from a `Clock`, randomness
//! injected. Every mutating call runs in one store transaction; engine events are sent after
//! it is durable. A failed transaction drops the in-memory caches, which reload from the store.

pub(crate) mod blobs;
pub(crate) mod clock;
pub(crate) mod groups;
pub(crate) mod held;
pub(crate) mod index;
pub(crate) mod journal;
pub(crate) mod pages;
pub(crate) mod large;
mod read;
pub(crate) mod records;
pub(crate) mod secrets;
pub(crate) mod state;
pub(crate) mod write;

pub use large::LiveTrees;
pub use write::Mutation;

use crate::apply::Reason;
use crate::error::{Error, Result};
use crate::events::{Event, Events, Origin};
use crate::identity::Identity;
use clock::Hlc;
use osis_commit::{CommitBlob, Form, Header};
use osis_core::{Ak, Clock, CommitId, Tid, Ts, WallMs};
use osis_crdt::{Dot, Fragment, SourceKind};
use osis_crypto::{CryptoRngCore, SeededRng};
use osis_keys::ActorEpochs;
use journal::{JMap, JNested, JSet, JSetMap, Journaled};
use osis_perm::Timelines;
use osis_store::{AspectUnit, Backend, RootStorage, Shred, Store, StoreConfig, Transaction};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::mpsc::Receiver;

/// Engine configuration.
#[derive(Clone, Debug)]
pub struct Config {
    /// `/node` software revision.
    pub software: String,
    pub store: StoreConfig,
}

impl Default for Config {
    fn default() -> Config {
        Config { software: format!("osis-node {}", env!("CARGO_PKG_VERSION")), store: StoreConfig::default() }
    }
}

/// An applied commit as the engine indexes it.
#[derive(Clone, Debug)]
pub(crate) struct Meta {
    pub header: Arc<Header>,
    pub received: WallMs,
    pub origin: Origin,
    /// Validity per aspect (spec/permissions.md §5.2).
    pub valid: Vec<bool>,
    /// Parts dropped (purge, expiry, keep at most): they count as held.
    pub dropped: BTreeSet<(usize, usize)>,
}

/// Owner of writes: one delta of one node (`[lo, hi)`), a commit-form commit, or exact dots of
/// one node (writes snapshots carry, `ctrs` sorted).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Owned {
    Node { node: Tid, lo: u64, hi: u64 },
    Commit(CommitId),
    Dots { src: osis_crdt::Source, ctrs: Vec<u64> },
}

impl Owned {
    pub fn of(h: &Header, id: &CommitId, ai: usize) -> Option<Owned> {
        let a = h.aspects.get(ai)?;
        Some(match h.form {
            Form::Node => Owned::Node { node: h.author, lo: a.lo, hi: a.hi },
            Form::Commit => Owned::Commit(*id),
        })
    }
    /// Whether `d` (an owner dot, never `Derived`) belongs to this delta.
    pub fn owns(&self, d: &Dot) -> bool {
        match (self, d.src.kind()) {
            (Owned::Node { node, lo, hi }, SourceKind::Node(t)) => t == node && *lo <= d.ctr && d.ctr < *hi,
            (Owned::Commit(c), SourceKind::Commit(x)) => c == x,
            (Owned::Dots { src, ctrs }, _) => d.src == *src && ctrs.binary_search(&d.ctr).is_ok(),
            _ => false,
        }
    }
    /// Whether a dot of `src` with a counter in `lo..hi` belongs to this delta.
    pub fn owns_range(&self, src: &osis_crdt::Source, lo: u64, hi: u64) -> bool {
        match (self, src.kind()) {
            (Owned::Node { node, lo: a, hi: b }, SourceKind::Node(t)) => t == node && lo < *b && *a < hi,
            (Owned::Commit(c), SourceKind::Commit(x)) => c == x,
            (Owned::Dots { src: s, ctrs }, _) => s == src && ctrs.get(ctrs.partition_point(|c| *c < lo)).is_some_and(|c| *c < hi),
            _ => false,
        }
    }
}

/// Applies `$m` to every journaled index of a `Core`.
macro_rules! journaled {
    ($c:expr, $m:ident) => {{
        let c = &mut *$c;
        c.held.$m();
        c.commits.$m();
        c.invalid.$m();
        c.by_aspect.$m();
        c.snapshots.$m();
        c.carried.$m();
        c.by_thing.$m();
        c.ranges.$m();
        c.pending.$m();
        c.syncing.$m();
        c.void.$m();
        c.valueless.$m();
        c.secrets.$m();
        c.own_keys.$m();
        c.was.$m();
        c.was_of.$m();
        c.moved.$m();
        c.groups.$m();
        c.member_keys.$m();
        c.unresolved.$m();
        c.rotation_role.$m();
        c.grant_overreach.$m();
        c.box_keys.$m();
        c.boxes_to.$m();
        c.epoch_intro.$m();
        c.box_written.$m();
        c.authors.$m();
        c.lost_due.$m();
        c.departures.$m();
        c.secrets_unresolved.$m();
    }};
}

/// A held compaction snapshot of an aspect: `ts`, ID, frontiers.
pub(crate) type HeldSnapshot = (Ts, CommitId, osis_crdt::Frontiers);

/// A scan callback: key (without prefix), value.
type ScanFn<'f> = dyn FnMut(&[u8], Vec<u8>) -> Result<()> + 'f;

/// A decoded commit record: received, origin, dropped parts, blob.
pub(crate) type CommitRecord = (WallMs, Origin, BTreeSet<(usize, usize)>, CommitBlob);

/// In-memory state over the store: caches and indexes, rebuilt by `load`. The indexes are
/// journaled (`journal`): a failed transaction undoes its own changes to them.
pub(crate) struct Core {
    pub id: Identity,
    pub hlc: Hlc,
    pub states: HashMap<(Tid, Ak), Option<Fragment>>,
    /// Page indexes of the cached states kept paged in the store.
    pub pages: HashMap<(Tid, Ak), pages::PageIndex>,
    /// Perm inputs: applied membership commits, roster snapshots, `/created` records.
    pub held: held::Held,
    pub timelines: Timelines,
    /// Components with fewer commits and snapshots are not saved (`index::WALK_CACHE_MIN`;
    /// tests lower it).
    pub walk_cache_min: usize,
    /// Saved walks the running transaction writes, for `Timelines::saved` once it is durable.
    pub walks_done: Option<osis_perm::SaveDone>,
    /// The running transaction called `touch` (`rollback` drops the caches).
    pub dirty: bool,
    /// The paged maps' key index hash key, derived from the node's seed.
    pub key_salt: [u8; 32],
    pub commits: JMap<CommitId, Meta>,
    /// Commits with a part invalid here, per aspect (`Core::index_validity`), so a join finds the
    /// writes to strip in O(invalid parts), not O(history).
    pub invalid: JSetMap<(Tid, Ak), CommitId>,
    /// Held deltas per aspect: (`ts`, commit).
    pub by_aspect: JSetMap<(Tid, Ak), (Ts, CommitId)>,
    /// Compaction snapshots held per aspect, with their frontiers: the bodies carrying a write
    /// besides its own (deaths, spec/commits.md §5).
    pub snapshots: JMap<(Tid, Ak), Vec<HeldSnapshot>>,
    /// Writes held snapshots carry whose own commit is not held, per aspect, judged as their
    /// authors' (spec/permissions.md §5.2: a snapshot vouches for nothing).
    pub carried: JMap<(Tid, Ak), Vec<crate::apply::validity::Carried>>,
    /// Held commits per thing they hold a delta of (re-judging a thing's deltas).
    pub by_thing: JSetMap<Tid, CommitId>,
    /// Node-form ranges per (tid, ak, node): lo -> (hi, commit).
    pub ranges: JNested<(Tid, Ak, Tid), u64, (u64, CommitId)>,
    pub pending: JMap<CommitId, Reason>,
    pub syncing: JSet<Tid>,
    pub void: JSet<CommitId>,
    /// What validity may have changed for since the last `rejudge_all`: things whose timeline
    /// changed, commits whose other inputs changed (void, required roles, overreach), or
    /// everything (a rebuild at open).
    pub stale_things: BTreeSet<Tid>,
    pub stale_commits: BTreeSet<CommitId>,
    pub stale_all: bool,
    /// Deltas whose value-carrying writes are held value-less (expired, purged).
    pub valueless: JMap<(Tid, Ak), Vec<Owned>>,
    /// Actors with secrets of their own whose epochs this node holds.
    pub secrets: JMap<Tid, ActorEpochs>,
    /// Things known to have secrets of their own (a `/keys` with keysets).
    pub own_keys: JSet<Tid>,
    /// `/was` index: t -> things whose `/was` reads t.
    pub was: JSetMap<Tid, Tid>,
    /// The `/was` each thing reads.
    pub was_of: JMap<Tid, Tid>,
    pub moved: JMap<Tid, Tid>,
    /// `/group` definitions and `/groups` (thing -> groups containing it, transitively).
    pub groups: groups::Groups,
    /// Keyed `/members` entries seen: (target, entry dot) -> (member, created value).
    pub member_keys: JMap<(Tid, Dot), (Tid, Option<osis_core::Value>)>,
    /// Membership commits whose removed keys are not known yet.
    pub unresolved: JSet<CommitId>,
    /// Box keys of keyed `/secrets` entries: (actor, entry dot) -> key.
    pub box_keys: JMap<(Tid, Dot), osis_core::Value>,
    /// Keyed boxes per member: member -> (actor, box key), from `/secrets` entries seen.
    pub boxes_to: JSetMap<Tid, (Tid, osis_core::Value)>,
    /// The earliest noted commit boxing an epoch or writing its keyset: (actor, role, epoch) ->
    /// (`ts`, author node, actor acted for). What introduced the epoch (`rotation`).
    pub epoch_intro: EpochIntro,
    /// Commit-form sources whose writes snapshots may carry, per thing: (thing, commit ID) ->
    /// (the node its writes are judged as, at which `ts`): a commit-form commit's author and
    /// `ts`, an import origin's importer and import `ts`, else a held snapshot's `Authors`
    /// (spec/crdt.md §8).
    pub authors: JMap<(Tid, CommitId), (Tid, Ts)>,
    /// The earliest noted commit writing a box: (actor, box key) -> its `ts`.
    pub box_written: JMap<(Tid, osis_schema::core_types::BoxKey), Ts>,
    /// Linked tenure frontiers decoded (by link content hash) with their canonical size; content
    /// addressed, so never stale.
    pub frontiers: BTreeMap<[u8; 32], (Arc<osis_perm::Frontier>, usize)>,
    /// Things a roster snapshot of which was kept out of perm for a linked frontier not held
    /// here (`validity::add_membership`): no roster snapshot of them is written.
    pub frontier_unknown: BTreeSet<Tid>,
    /// `rotation::departures` per actor with the time it holds until (an edge's `until`, a
    /// write's future `ts`); cleared by `membership_changed`.
    pub departures: JMap<Tid, (Vec<osis_keys::Departure>, Option<WallMs>)>,
    /// `/secrets` writes of applied commits waiting for the keys of the boxes they remove.
    pub secrets_unresolved: JMap<(CommitId, usize), crate::apply::keys::Unresolved>,
    /// Roles `/secrets` and `/keys` deltas need (by commit and aspect index).
    pub rotation_role: JMap<(CommitId, usize), osis_core::Role>,
    /// `/secrets` parts of membership commits that write beyond their grantees' boxes (an invite
    /// grant may carry only those, spec/permissions.md §2).
    pub grant_overreach: JSet<(CommitId, usize)>,
    /// Schemas of local writes (typed views for undo).
    pub schemas: BTreeMap<osis_core::SchemaId, Arc<osis_schema::Schema>>,
    pub events: Events,
    /// States the running transaction wrote (dropped from the cache on rollback).
    pub written: Vec<(Tid, Ak)>,
    /// Tests: let local commits break the writer-side membership rules (to test receivers).
    pub skip_writer_rules: bool,
    /// Tests: after each per-entry `/secrets` ingestion, check that ingesting the whole state
    /// learns nothing more (`apply::atomic::observe_secrets_keys`).
    #[cfg(test)]
    pub check_ingest: bool,
    /// Key actors other than the node whose seed this node holds for now (a recovery key from
    /// its card, a link key; membership flows): they sign commits (`Mutation::sign_as`) and
    /// open their boxes. In memory only.
    pub key_actors: BTreeMap<Tid, Arc<Identity>>,
    /// The lost-access trigger's work list (`rotation::LOST_DUE`).
    pub lost_due: JSet<Tid>,
    /// `Engine::live_trees` per thing, cleared by every transaction that changes the indexes or
    /// a state (`touch`, `rollback`) and when blobs arrive (`put_blobs`).
    pub live_trees: BTreeMap<Tid, LiveTrees>,
    /// `Engine::bodies` per commit without their plaintexts (the label pass's cost): dropped
    /// when the commit's record is written (late parts, drops), when a thing it touches gets
    /// its creation record, and all when an actor gets secrets of its own (reader actors move);
    /// only commits whose things' owner chains are known are kept.
    pub bodies: BTreeMap<CommitId, Vec<crate::labeling::Body>>,
    /// `Engine::body_live` per body, forgotten per aspect when its state changes (`forget_live`)
    /// and wholly on rollback
    /// (`touch`, `rollback`).
    pub live_bodies: BTreeMap<(CommitId, Tid, Ak), bool>,
    /// Bumped whenever a transaction changes the indexes or a state, or rolls back: caches
    /// derived from them (the sync engine's co-readers) compare it.
    pub generation: u64,
}

/// (actor, role, epoch) -> the commit that introduced it: (ts, author node, actor, commit ID).
pub(crate) type EpochIntro = JMap<(Tid, osis_core::Role, osis_crypto::Epoch), (Ts, Tid, Tid, CommitId)>;

impl Core {
    /// Drops what is derived from rosters, `/secrets` and held epochs (the departures cache):
    /// called wherever those change.
    pub fn membership_changed(&mut self) {
        if !self.departures.is_empty() {
            self.departures.retain(|_, _| false);
        }
    }

    /// Re-evaluates the timelines around the things whose held inputs changed; the things of
    /// changed timelines wait for `rejudge_all`.
    pub fn update_timelines(&mut self) {
        let touched = self.held.take_touched();
        if !touched.is_empty() {
            let changed = self.timelines.update_touched(&self.held, &touched);
            self.stale_things.extend(changed.evaluated);
            // a walk that only went on changed authority only below what it touched
            let below = self.held.reach(&changed.extended);
            self.stale_things.extend(below);
        }
        self.membership_changed();
    }

    /// Whether some validity waits for `rejudge_all`.
    pub fn stale(&self) -> bool {
        self.stale_all || !self.stale_things.is_empty() || !self.stale_commits.is_empty()
    }

    /// Forgets the cached liveness of every body with a delta on `(tid, ak)` (its state
    /// changed): a body's liveness spans every aspect of its class, whichever one was asked.
    pub fn forget_live(&mut self, tid: &Tid, ak: &Ak) {
        let commits = &self.commits;
        self.live_bodies.retain(|(c, t, a), _| {
            if t == tid && a == ak {
                return false;
            }
            !commits.get(c).is_some_and(|m| m.header.aspects.iter().any(|x| x.tid == *tid && x.ak == *ak))
        });
    }

    /// Notes that the running transaction changes the indexes or a state (drops derived caches).
    pub fn touch(&mut self) {
        self.live_trees.clear();
        self.generation += 1;
        self.dirty = true;
    }

    /// The running transaction committed: its journal is forgotten.
    fn commit_journal(&mut self) {
        journaled!(self, commit);
        self.written.clear();
        self.dirty = false;
    }

    /// Undoes the aborted transaction's changes to the caches and indexes (the caches stay when
    /// it changed nothing: a failed read keeps them).
    fn rollback(&mut self) {
        if self.dirty || !self.written.is_empty() {
            self.dirty = false;
            self.live_trees.clear();
            self.live_bodies.clear();
            self.bodies.clear();
            self.generation += 1;
            self.membership_changed();
            for k in std::mem::take(&mut self.written) {
                self.states.remove(&k);
                self.pages.remove(&k);
            }
        }
        journaled!(self, rollback);
        // the timelines follow the restored held set; validity flags are restored with `commits`
        let touched = self.held.take_touched();
        if !touched.is_empty() {
            self.timelines.update_touched(&self.held, &touched);
        }
        self.stale_things.clear();
        self.stale_commits.clear();
    }

    fn new(id: Identity, clock: Arc<dyn Clock>) -> Core {
        let key_salt = osis_core::hash::derive_key("osis node key index", id.seed().expose());
        Core {
            id,
            hlc: Hlc::new(clock, Ts::default()),
            states: HashMap::new(),
            pages: HashMap::new(),
            held: held::Held::default(),
            timelines: Timelines::new(),
            walk_cache_min: index::WALK_CACHE_MIN,
            walks_done: None,
            stale_things: BTreeSet::new(),
            stale_commits: BTreeSet::new(),
            stale_all: true,
            dirty: false,
            key_salt,
            commits: JMap::default(),
            invalid: JSetMap::default(),
            by_aspect: JSetMap::default(),
            snapshots: JMap::default(),
            carried: JMap::default(),
            by_thing: JSetMap::default(),
            ranges: JNested::default(),
            pending: JMap::default(),
            syncing: JSet::default(),
            void: JSet::default(),
            valueless: JMap::default(),
            secrets: JMap::default(),
            own_keys: JSet::default(),
            was: JSetMap::default(),
            was_of: JMap::default(),
            moved: JMap::default(),
            groups: groups::Groups::default(),
            member_keys: JMap::default(),
            unresolved: JSet::default(),
            rotation_role: JMap::default(),
            grant_overreach: JSet::default(),
            box_keys: JMap::default(),
            boxes_to: JSetMap::default(),
            epoch_intro: JMap::default(),
            box_written: JMap::default(),
            authors: JMap::default(),
            departures: JMap::default(),
            frontiers: BTreeMap::new(),
            frontier_unknown: BTreeSet::new(),
            secrets_unresolved: JMap::default(),
            schemas: BTreeMap::new(),
            events: Events::default(),
            written: Vec::new(),
            skip_writer_rules: false,
            #[cfg(test)]
            check_ingest: false,
            key_actors: BTreeMap::new(),
            lost_due: JSet::default(),
            live_trees: BTreeMap::new(),
            bodies: BTreeMap::new(),
            live_bodies: BTreeMap::new(),
            generation: 0,
        }
    }

    pub fn now(&self) -> WallMs {
        self.hlc.wall()
    }

    /// Re-indexes which parts of commit `id` are invalid here (call after setting `Meta::valid`).
    pub fn index_validity(&mut self, id: &CommitId) {
        let Some(m) = self.commits.get(id) else { return };
        for (ai, a) in m.header.aspects.iter().enumerate() {
            let k = (a.tid, a.ak.clone());
            if m.valid.get(ai).copied().unwrap_or(false) {
                self.invalid.remove(&k, id);
            } else {
                self.invalid.insert(k, *id);
            }
        }
    }

    /// The commit that wrote dot `d` on `(tid, ak)`, if held.
    pub fn commit_of(&self, tid: &Tid, ak: &Ak, d: &Dot) -> Option<CommitId> {
        let d = d.owner();
        match d.src.kind() {
            SourceKind::Commit(c) => Some(*c),
            SourceKind::Node(n) => {
                let m = self.ranges.get(&(*tid, ak.clone(), *n))?;
                let (_, (hi, c)) = m.range(..=d.ctr).next_back()?;
                (d.ctr < *hi).then_some(*c)
            }
            SourceKind::Derived(_) => None,
        }
    }
}

/// One transaction with the engine's in-memory state.
pub(crate) struct Tx<'a> {
    pub txn: Transaction<'a>,
    pub core: &'a mut Core,
    pub rng: &'a mut dyn CryptoRngCore,
}

impl Tx<'_> {
    /// Loads the state of `(tid, ak)` into the cache: a paged state lazily (its skeleton; pages
    /// as `ensure_*` and `load` need them).
    pub fn load_lazy(&mut self, tid: &Tid, ak: &Ak) -> Result<()> {
        let k = (*tid, ak.clone());
        if self.core.states.contains_key(&k) {
            return Ok(());
        }
        let f = match self.txn.get_aspect(tid, ak)? {
            Some(mut u) if pages::is_paged(&u.state) => {
                // an earlier build's layout is laid out anew, once
                if let Some(whole) = pages::legacy(&mut self.txn, tid, ak, &u.state)? {
                    self.core.touch();
                    self.core.written.push(k.clone());
                    u.state = pages::write_full(&mut self.txn, tid, ak, Some(&whole), true, &self.core.key_salt)?.0;
                    self.txn.put_aspect(tid, ak, &u, Shred::No)?;
                }
                let (f, idx) = pages::open(&u.state, &self.core.key_salt)?;
                self.core.pages.insert(k.clone(), idx);
                Some(f)
            }
            Some(u) if !u.state.is_empty() => Some(state::decode(&u.state)?),
            _ => None,
        };
        self.core.states.insert(k, f);
        Ok(())
    }

    /// Runs `g` on the cached state of `(tid, ak)` (taken out of the cache meanwhile) and its page
    /// index; nothing for an unpaged state.
    fn with_pages<T>(&mut self, tid: &Tid, ak: &Ak, g: impl FnOnce(&mut Transaction<'_>, &mut pages::PageIndex, &mut Fragment) -> Result<T>) -> Result<Option<T>> {
        let k = (*tid, ak.clone());
        let Some(idx) = self.core.pages.get_mut(&k) else { return Ok(None) };
        let Some(mut f) = self.core.states.get_mut(&k).and_then(Option::take) else { return Ok(None) };
        let r = g(&mut self.txn, idx, &mut f);
        self.core.states.insert(k, Some(f));
        r.map(Some)
    }

    /// Loads the whole state of `(tid, ak)` into the cache.
    pub fn load(&mut self, tid: &Tid, ak: &Ak) -> Result<()> {
        self.load_lazy(tid, ak)?;
        if self.core.pages.get(&(*tid, ak.clone())).is_some_and(|i| !i.whole()) {
            self.with_pages(tid, ak, |txn, idx, f| pages::load_all(txn, tid, ak, idx, f))?;
        }
        Ok(())
    }

    /// Loads what ops at `paths` (op path segments) read and write (`pages::ensure_path`).
    pub fn ensure_paths(&mut self, tid: &Tid, ak: &Ak, paths: &[Vec<osis_crdt::PathSeg>]) -> Result<()> {
        self.load_lazy(tid, ak)?;
        if !self.core.pages.get(&(*tid, ak.clone())).is_some_and(|i| !i.whole()) {
            return Ok(());
        }
        let ok = self.with_pages(tid, ak, |txn, idx, f| {
            for p in paths {
                if !pages::ensure_path(txn, tid, ak, idx, f, p)? {
                    return Ok(false);
                }
            }
            Ok(true)
        })?;
        if ok == Some(false) {
            self.load(tid, ak)?;
        }
        Ok(())
    }

    /// Loads what joining a delta with this touch reads and rewrites (`pages::ensure_touch`;
    /// `None`: everything).
    pub fn ensure_touch(&mut self, tid: &Tid, ak: &Ak, touch: &pages::Touch) -> Result<()> {
        self.load_lazy(tid, ak)?;
        if !self.core.pages.get(&(*tid, ak.clone())).is_some_and(|i| !i.whole()) {
            return Ok(());
        }
        let ok = match touch {
            Some(t) => self.with_pages(tid, ak, |txn, idx, f| pages::ensure_touch(txn, tid, ak, idx, f, t))? == Some(true),
            None => false,
        };
        if !ok {
            self.load(tid, ak)?;
        }
        Ok(())
    }

    /// The cached state as loaded so far (after `load_lazy` and `ensure_*`).
    pub fn cached(&self, tid: &Tid, ak: &Ak) -> Option<&Fragment> {
        self.core.states.get(&(*tid, ak.clone())).and_then(Option::as_ref)
    }

    /// The whole state of `(tid, ak)`.
    pub fn state(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<&Fragment>> {
        self.load(tid, ak)?;
        Ok(self.core.states.get(&(*tid, ak.clone())).and_then(Option::as_ref))
    }

    /// Writes a whole state (keeping the unit's undo buffer unless `clear_undo`); `f` is the
    /// whole state.
    pub fn set_state(&mut self, tid: &Tid, ak: &Ak, f: Option<Fragment>, shred: Shred, clear_undo: bool) -> Result<()> {
        self.core.touch();
        self.core.forget_live(tid, ak);
        if osis_schema::core_types::is_membership_class(ak.as_str()) {
            self.core.membership_changed();
        }
        self.core.written.push((*tid, ak.clone()));
        let mut unit = self.txn.get_aspect(tid, ak)?.unwrap_or_default();
        let (bytes, idx) = pages::write_full(&mut self.txn, tid, ak, f.as_ref(), pages::is_paged(&unit.state), &self.core.key_salt)?;
        unit.state = bytes;
        match idx {
            Some(idx) => self.core.pages.insert((*tid, ak.clone()), idx),
            None => self.core.pages.remove(&(*tid, ak.clone())),
        };
        if clear_undo {
            unit.undo.clear();
        }
        self.txn.put_aspect(tid, ak, &unit, shred)?;
        let ik = records::aspect_key(b"a/", tid, ak);
        if f.is_some() {
            self.txn.put_local(&ik, &[], Shred::No)?;
        } else {
            self.txn.remove_local(&ik, Shred::No)?;
        }
        self.core.states.insert((*tid, ak.clone()), f);
        Ok(())
    }

    /// Writes a state a join changed: `touch` (`pages::touch_of` the delta) says what it
    /// changed. A paged state rewrites only those pages (and its skeleton if needed); anything
    /// else is written whole (the pages not loaded joined in first). The caller has noted the
    /// state as written (`Core::written`).
    pub fn set_state_touched(&mut self, tid: &Tid, ak: &Ak, f: Option<Fragment>, touch: &pages::Touch, shred: Shred) -> Result<()> {
        self.core.forget_live(tid, ak);
        if osis_schema::core_types::is_membership_class(ak.as_str()) {
            self.core.membership_changed();
        }
        let k = (*tid, ak.clone());
        if let (Some(st), Some(idx), Some(touch)) = (&f, self.core.pages.get_mut(&k), touch)
            && let Some(unit_state) = pages::write_touched(&mut self.txn, idx, tid, ak, st, touch, shred)?
        {
            if let Some(s) = unit_state {
                let mut unit = self.txn.get_aspect(tid, ak)?.unwrap_or_default();
                unit.state = s;
                self.txn.put_aspect(tid, ak, &unit, shred)?;
            }
            self.core.states.insert(k, f);
            return Ok(());
        }
        let mut f = f;
        if let (Some(st), Some(idx)) = (&mut f, self.core.pages.get_mut(&k)) {
            pages::load_all(&mut self.txn, tid, ak, idx, st)?;
        }
        self.set_state(tid, ak, f, shred, false)
    }

    /// Rewrites shredded what of the state of `(tid, ak)` may hold copies of a dropped body's
    /// writes (`bodies`: its deltas), and clears the undo buffer (spec/commits.md §5: dropping a
    /// body destroys every local copy; the state's content is unchanged). A paged state rewrites
    /// the pages holding the bodies' dots and its skeleton; anything else is rewritten whole.
    pub fn shred_bodies(&mut self, tid: &Tid, ak: &Ak, bodies: &[Fragment]) -> Result<()> {
        self.load_lazy(tid, ak)?;
        let k = (*tid, ak.clone());
        let touches: Option<Vec<osis_crdt::PagedTouch>> = match self.core.pages.get(&k) {
            Some(idx) => bodies.iter().map(|d| pages::touch_of(d, Some(idx))).collect(),
            None => None,
        };
        if let Some(touches) = touches {
            for t in &touches {
                self.ensure_touch(tid, ak, &Some(t.clone()))?;
            }
            self.core.touch();
            self.core.written.push(k.clone());
            let done = self.with_pages(tid, ak, |txn, idx, f| {
                for t in &touches {
                    if pages::write_touched(txn, idx, tid, ak, f, t, Shred::Yes)?.is_none() {
                        return Ok(false);
                    }
                }
                pages::unindex(txn, idx, tid, ak, f, bodies)?;
                let mut unit = txn.get_aspect(tid, ak)?.unwrap_or_default();
                unit.state = pages::skeleton_unit(f, idx)?;
                unit.undo.clear();
                txn.put_aspect(tid, ak, &unit, Shred::Yes)?;
                Ok(true)
            })?;
            if done == Some(true) {
                return Ok(());
            }
        }
        self.load(tid, ak)?;
        let st = self.core.states.get(&k).cloned().flatten();
        self.set_state(tid, ak, st, Shred::Yes, true)
    }

    /// Holds value-less the writes of `(tid, ak)` that `owned` owns (a delta expired or
    /// purged, spec/crdt.md §4.7), shredding every copy of their values; `bodies` are the deltas
    /// owning them (where they lie). A paged state strips and rewrites only their pages and
    /// its skeleton; anything else is rewritten whole.
    pub fn strip_bodies(&mut self, tid: &Tid, ak: &Ak, bodies: &[Fragment], owned: &crate::engine::Owned) -> Result<()> {
        self.load_lazy(tid, ak)?;
        let k = (*tid, ak.clone());
        let touches: Option<Vec<osis_crdt::PagedTouch>> = match self.core.pages.get(&k) {
            Some(idx) => bodies.iter().map(|d| pages::touch_of(d, Some(idx))).collect(),
            None => None,
        };
        let pred = |d: &osis_crdt::Dot| owned.owns(d);
        if let Some(touches) = touches {
            for t in &touches {
                self.ensure_touch(tid, ak, &Some(t.clone()))?;
            }
            self.core.touch();
            self.core.written.push(k.clone());
            let done = self.with_pages(tid, ak, |txn, idx, f| {
                if !pages::strip_touched(txn, idx, tid, ak, f, &touches, &pred)? {
                    return Ok(false);
                }
                let mut unit = txn.get_aspect(tid, ak)?.unwrap_or_default();
                unit.state = pages::skeleton_unit(f, idx)?;
                unit.undo.clear();
                txn.put_aspect(tid, ak, &unit, Shred::Yes)?;
                Ok(true)
            })?;
            if done == Some(true) {
                return Ok(());
            }
        }
        self.load(tid, ak)?;
        if let Some(mut st) = self.core.states.get(&k).cloned().flatten() {
            st.strip(&pred);
            self.set_state(tid, ak, Some(st), Shred::Yes, true)?;
        }
        Ok(())
    }

    pub fn unit(&mut self, tid: &Tid, ak: &Ak) -> Result<AspectUnit> {
        Ok(self.txn.get_aspect(tid, ak)?.unwrap_or_default())
    }

    /// Writes a commit record: what the engine indexes of it (`index::record_head`: received,
    /// origin, dropped parts, per part its validity and roles) and its blob.
    /// Writes a commit record, and for a membership commit its `node/edges` row (`edges`: what
    /// the caller already read of `blob` with `edge_parts_of`, else decoded here).
    pub fn put_commit(&mut self, id: &CommitId, blob: &CommitBlob, meta: &Meta, shred: Shred, edges: Option<&crate::apply::validity::EdgeParts>) -> Result<()> {
        self.core.bodies.remove(id);
        let v = [index::record_head(meta), blob.encode()].concat();
        self.txn.put_local(&records::commit_key(id), &v, shred)?;
        if meta.header.kind.is_membership() {
            // perm's reading of it, persisted beside the record (an open decodes no body)
            match edges {
                Some(p) => index::put_edges(self, id, p, shred)?,
                None => {
                    let p = crate::apply::edge_parts_of(self, id, &meta.header, blob.clone())?;
                    index::put_edges(self, id, &p, shred)?;
                }
            }
        }
        Ok(())
    }

    /// Removes a commit record (shredded) with what the index keeps beside it.
    pub fn remove_commit(&mut self, id: &CommitId) -> Result<()> {
        self.core.bodies.remove(id);
        self.txn.remove_local(&records::commit_key(id), Shred::Yes)?;
        index::remove_edges(self, id)
    }

    pub fn get_commit(&mut self, id: &CommitId) -> Result<Option<CommitBlob>> {
        let Some(v) = self.txn.get_local(&records::commit_key(id))? else { return Ok(None) };
        Ok(Some(decode_commit_record(&v)?.3))
    }

    /// Scans local records under `prefix` (keys returned without it).
    pub fn scan(&mut self, prefix: &[u8], mut f: impl FnMut(&[u8], Vec<u8>) -> Result<()>) -> Result<()> {
        scan_local(&mut self.txn, prefix, &mut f)
    }

    pub fn now(&self) -> WallMs {
        self.core.now()
    }
}

fn scan_local(txn: &mut Transaction<'_>, prefix: &[u8], f: &mut ScanFn<'_>) -> Result<()> {
    let mut from: Vec<u8> = Vec::new();
    loop {
        let page = txn.scan_local(prefix, &from, 256)?;
        let n = page.len();
        for (k, v) in page {
            let tail = k.get(prefix.len()..).unwrap_or_default();
            from = [tail, &[0]].concat();
            f(tail, v)?;
        }
        if n < 256 {
            return Ok(());
        }
    }
}

/// `(received, origin, dropped, blob)`.
pub(crate) fn decode_commit_record(v: &[u8]) -> Result<CommitRecord> {
    let (head, rest) = index::parse_head(v)?;
    let blob = CommitBlob::decode(rest).map_err(|_| Error::Corrupt("commit blob"))?;
    Ok((head.received, head.origin, head.dropped, blob))
}

/// One node's engine.
pub struct Engine {
    store: Store,
    store_rng: SeededRng,
    rng: Box<dyn CryptoRngCore + Send>,
    pub(crate) core: Core,
    clock: Arc<dyn Clock>,
    cfg: Config,
}

impl Engine {
    /// A new node over an empty backend: fresh identity, its node thing with `/created`,
    /// `/node` and `/keys` (spec/permissions.md §4 node card).
    pub fn create(backend: Box<dyn Backend>, root: Box<dyn RootStorage>, cfg: Config, clock: Arc<dyn Clock>, mut rng: Box<dyn CryptoRngCore + Send>) -> Result<Engine> {
        let store = Store::create(backend, root, cfg.store, &mut *rng)?;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let store_rng = SeededRng::from_seed(seed);
        let id = Identity::generate(&mut *rng);
        let mut e = Engine { store, store_rng, rng, core: Core::new(id, clock.clone()), clock, cfg };
        let seed_bytes = e.core.id.seed().expose().to_vec();
        // a new store: its (empty) persisted index is current
        e.run(|tx| {
            tx.txn.put_local(records::SEED, &seed_bytes, Shred::No)?;
            index::write_all(tx)
        })?;
        e.bootstrap()?;
        Ok(e)
    }

    /// Opens an existing node and re-examines its pending commits.
    pub fn open(backend: Box<dyn Backend>, root: Box<dyn RootStorage>, cfg: Config, clock: Arc<dyn Clock>, mut rng: Box<dyn CryptoRngCore + Send>) -> Result<Engine> {
        let mut store = Store::open(backend, root, cfg.store)?;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let mut store_rng = SeededRng::from_seed(seed);
        let s = {
            let mut txn = store.transaction(&mut store_rng)?;
            txn.get_local(records::SEED)?.ok_or(Error::Corrupt("no seed"))?
        };
        let s: [u8; 32] = s.as_slice().try_into().map_err(|_| Error::Corrupt("seed"))?;
        let id = Identity::from_seed(osis_crypto::Secret32::from_bytes(s));
        let mut e = Engine { store, store_rng, rng, core: Core::new(id, clock.clone()), clock, cfg };
        e.reload()?;
        e.reexamine()?;
        Ok(e)
    }

    /// The node thing's first commits: `/created` with `/node`, then `/keys` (its KEM key).
    fn bootstrap(&mut self) -> Result<()> {
        use osis_schema::core_types as ct;
        let node = self.tid();
        let mut m = Mutation::new();
        m.create(self.core.id.record().clone());
        m.set(node, &ct::NODE, &ct::NodeInfo { software: self.cfg.software.clone(), schemas: BTreeMap::new() })?;
        self.commit(m)?;
        let kem = self.core.id.keys().kem.public();
        let mut k = Mutation::new();
        k.set(node, &ct::KEYS, &ct::Keys { key: Some(ct::KemKey::X25519MlKem768(kem.as_bytes().to_vec())), ..Default::default() })?;
        self.commit(k)?;
        Ok(())
    }

    /// Registers an app schema: typed views for undo and default bounds for snapshots of its
    /// AKs (local writes through typed keys register theirs).
    pub fn register_schema(&mut self, s: Arc<osis_schema::Schema>) {
        self.core.schemas.insert(s.id, s);
    }

    /// A local record of the API layer (`osis`), never synced.
    pub fn app_record(&mut self, name: &str) -> Result<Option<Vec<u8>>> {
        let k = [records::APP, name.as_bytes()].concat();
        self.run(|tx| Ok(tx.txn.get_local(&k)?))
    }

    /// Every key the store's current tree yields: what an attacker holding the device starts
    /// from. Shredding tests.
    #[doc(hidden)]
    pub fn forensic_keys(&mut self) -> Result<Vec<[u8; 32]>> {
        Ok(self.store.forensic_keys()?)
    }

    /// Writes a local record of the API layer.
    pub fn set_app_record(&mut self, name: &str, value: &[u8]) -> Result<()> {
        let k = [records::APP, name.as_bytes()].concat();
        self.run(|tx| Ok(tx.txn.put_local(&k, value, Shred::No)?))
    }

    /// Reports a diagnostic of the API layer (deduped and rate-limited like the engine's).
    pub fn report(&mut self, d: crate::events::Diagnostic) {
        let now = self.now();
        self.core.events.diagnostic(d, now);
    }

    /// The owner of `tid` (`None`: a key actor or an unknown thing).
    pub fn owner(&self, tid: &Tid) -> Option<Tid> {
        self.core.owner(tid)
    }

    /// This node's tid.
    pub fn tid(&self) -> Tid {
        self.core.id.tid()
    }

    pub fn identity(&self) -> &Identity {
        &self.core.id
    }

    /// The corrected wall clock.
    pub fn now(&self) -> WallMs {
        self.core.now()
    }

    /// The clock correction from node-sync (spec/sync.md §6).
    pub fn set_clock_offset(&mut self, ms: i64) {
        self.core.hlc.set_offset(ms);
    }

    /// A channel of engine events, sent after durability.
    pub fn subscribe(&mut self) -> Receiver<Event> {
        self.core.events.subscribe()
    }

    /// Runs `f` in one store transaction; events go out once it is durable.
    pub(crate) fn run<T>(&mut self, f: impl FnOnce(&mut Tx<'_>) -> Result<T>) -> Result<T> {
        // changes made outside a transaction are not this one's to undo
        self.core.commit_journal();
        let stale_all = self.core.stale_all;
        let r = match self.store.transaction(&mut self.store_rng) {
            Ok(txn) => {
                let mut tx = Tx { txn, core: &mut self.core, rng: &mut *self.rng };
                // the persisted index follows the in-memory indexes in the same transaction
                let r = f(&mut tx);
                // every validity change was judged before the index is persisted
                debug_assert!(r.is_err() || (tx.core.stale_things.is_empty() && tx.core.stale_commits.is_empty()), "stale validity left unjudged: {:?} {:?}", tx.core.stale_things, tx.core.stale_commits);
                match r.and_then(|v| index::persist(&mut tx).map(|_| v)) {
                    Ok(v) => {
                        let Tx { txn, .. } = tx;
                        txn.commit().map(|_| v).map_err(Error::from)
                    }
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e.into()),
        };
        match r {
            Ok(v) => {
                if let Some(d) = self.core.walks_done.take() {
                    self.core.timelines.saved(d);
                }
                self.core.commit_journal();
                self.core.events.flush();
                Ok(v)
            }
            Err(e) => {
                self.core.walks_done = None;
                self.core.events.discard();
                self.core.rollback();
                self.core.stale_all = stale_all;
                Err(e)
            }
        }
    }

    /// A fresh `Core` loaded from the store (`rebuild`: ignoring the persisted index); whether
    /// it was rebuilt from the commit records.
    fn load_fresh(&mut self, rebuild: bool) -> Result<Option<Vec<(Tid, Ak)>>> {
        let id = Identity::from_seed(self.core.id.seed().clone());
        let mut fresh = Core::new(id, self.clock.clone());
        fresh.hlc = Hlc::new(self.clock.clone(), self.core.hlc.last());
        fresh.hlc.set_offset(self.core.hlc.offset());
        fresh.events = std::mem::take(&mut self.core.events);
        fresh.key_actors = std::mem::take(&mut self.core.key_actors);
        fresh.schemas = std::mem::take(&mut self.core.schemas);
        fresh.skip_writer_rules = self.core.skip_writer_rules;
        fresh.walk_cache_min = self.core.walk_cache_min;
        #[cfg(test)]
        {
            fresh.check_ingest = self.core.check_ingest;
        }
        self.core = fresh;
        let txn = self.store.transaction(&mut self.store_rng)?;
        let mut tx = Tx { txn, core: &mut self.core, rng: &mut *self.rng };
        let r = crate::apply::load(&mut tx, rebuild);
        self.core.commit_journal();
        r
    }

    /// Rebuilds every in-memory cache and index from the store (keeps identity, clock and
    /// subscribers).
    pub(crate) fn reload(&mut self) -> Result<()> {
        let rebuilt = match self.load_fresh(false) {
            Ok(r) => r,
            // a persisted index that does not decode is rebuilt from the commit records
            Err(Error::Corrupt(_)) => self.load_fresh(true)?,
            Err(e) => return Err(e),
        };
        if let Some(stale) = rebuilt {
            // states judged by other rules re-joined, then the index persisted for the next open
            self.run(|tx| {
                for (tid, ak) in &stale {
                    crate::apply::rejoin(tx, tid, ak)?;
                }
                index::write_all(tx)
            })?;
        } else if self.core.timelines.due(self.core.walk_cache_min) {
            // walks evaluated or continued at open saved for the next (a cache: a failure
            // leaves the open as it is)
            let _ = self.run(|_| Ok(()));
        }
        Ok(())
    }
}
