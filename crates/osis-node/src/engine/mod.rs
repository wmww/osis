//! The engine: one node's local state over its `Store` (notes/architecture.md §2: the node
//! talks to `Store` only). Synchronous, no I/O of its own, time from a `Clock`, randomness
//! injected. Every mutating call runs in one store transaction; engine events are sent after
//! it is durable. A failed transaction drops the in-memory caches, which reload from the store.

pub(crate) mod blobs;
pub(crate) mod clock;
pub(crate) mod groups;
pub(crate) mod held;
pub(crate) mod journal;
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
use records::{Rd, Wr};
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

/// Owner of writes: one delta of one node (`[lo, hi)`), or a commit-form commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Owned {
    Node { node: Tid, lo: u64, hi: u64 },
    Commit(CommitId),
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
        c.secrets_unresolved.$m();
    }};
}

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
    pub pages: HashMap<(Tid, Ak), state::PageIndex>,
    /// Perm inputs: applied membership commits, roster snapshots, `/created` records.
    pub held: held::Held,
    pub timelines: Timelines,
    /// Things whose timeline changed since their deltas were last judged (`rejudge_all`).
    pub rejudge: BTreeSet<Tid>,
    pub commits: JMap<CommitId, Meta>,
    /// Commits with a part invalid here, per aspect (`Core::index_validity`), so a join finds the
    /// writes to strip in O(invalid parts), not O(history).
    pub invalid: JSetMap<(Tid, Ak), CommitId>,
    /// Held deltas per aspect: (`ts`, commit).
    pub by_aspect: JSetMap<(Tid, Ak), (Ts, CommitId)>,
    /// Held commits per thing they hold a delta of (re-judging a thing's deltas).
    pub by_thing: JSetMap<Tid, CommitId>,
    /// Node-form ranges per (tid, ak, node): lo -> (hi, commit).
    pub ranges: JNested<(Tid, Ak, Tid), u64, (u64, CommitId)>,
    pub pending: JMap<CommitId, Reason>,
    pub syncing: JSet<Tid>,
    pub void: JSet<CommitId>,
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
    pub epoch_intro: JMap<(Tid, osis_core::Role, osis_crypto::Epoch), (Ts, Tid, Tid)>,
    /// The earliest noted commit writing a box: (actor, box key) -> its `ts`.
    pub box_written: JMap<(Tid, osis_schema::core_types::BoxKey), Ts>,
    /// Linked tenure frontiers decoded (by link content hash) with their canonical size; content
    /// addressed, so never stale.
    pub frontiers: BTreeMap<[u8; 32], (Arc<osis_perm::Frontier>, usize)>,
    /// Things a roster snapshot of which was kept out of perm for a linked frontier not held
    /// here (`validity::add_membership`): no roster snapshot of them is written.
    pub frontier_unknown: BTreeSet<Tid>,
    /// `rotation::departures` per actor with the time it holds until (an edge's `until`, a
    /// write's future `ts`); cleared by `membership_changed`. Not journaled: a rollback clears it.
    pub departures: BTreeMap<Tid, (Vec<osis_keys::Departure>, Option<WallMs>)>,
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
    /// Key actors other than the node whose seed this node holds for now (a recovery key from
    /// its card, a link key; membership flows): they sign commits (`Mutation::sign_as`) and
    /// open their boxes. In memory only.
    pub key_actors: BTreeMap<Tid, Arc<Identity>>,
    /// The lost-access trigger's work list (`rotation::LOST_DUE`; a superset after a rollback
    /// is harmless).
    pub lost_due: BTreeSet<Tid>,
    /// `Engine::live_trees` per thing, cleared by every transaction that changes the indexes or
    /// a state (`touch`, `rollback`) and when blobs arrive (`put_blobs`).
    pub live_trees: BTreeMap<Tid, LiveTrees>,
}

impl Core {
    /// Drops what is derived from rosters, `/secrets` and held epochs (the departures cache):
    /// called wherever those change.
    pub fn membership_changed(&mut self) {
        self.departures.clear();
    }

    /// Re-evaluates the timelines around the things whose held inputs changed; the things of
    /// changed timelines wait for `rejudge_all`.
    pub fn update_timelines(&mut self) {
        let touched = self.held.take_touched();
        if !touched.is_empty() {
            let changed = self.timelines.update_touched(&self.held, &touched);
            self.rejudge.extend(changed);
        }
        self.membership_changed();
    }

    /// Notes that the running transaction changes the indexes or a state (drops derived caches).
    pub fn touch(&mut self) {
        self.live_trees.clear();
    }

    /// The running transaction committed: its journal is forgotten.
    fn commit_journal(&mut self) {
        journaled!(self, commit);
        self.written.clear();
    }

    /// Undoes the aborted transaction's changes to the caches and indexes.
    fn rollback(&mut self) {
        self.live_trees.clear();
        self.membership_changed();
        for k in std::mem::take(&mut self.written) {
            self.states.remove(&k);
            self.pages.remove(&k);
        }
        journaled!(self, rollback);
        // the timelines follow the restored held set; validity flags are restored with `commits`
        let touched = self.held.take_touched();
        if !touched.is_empty() {
            self.timelines.update_touched(&self.held, &touched);
        }
        self.rejudge.clear();
    }

    fn new(id: Identity, clock: Arc<dyn Clock>) -> Core {
        Core {
            id,
            hlc: Hlc::new(clock, Ts::default()),
            states: HashMap::new(),
            pages: HashMap::new(),
            held: held::Held::default(),
            timelines: Timelines::new(),
            rejudge: BTreeSet::new(),
            commits: JMap::default(),
            invalid: JSetMap::default(),
            by_aspect: JSetMap::default(),
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
            departures: BTreeMap::new(),
            frontiers: BTreeMap::new(),
            frontier_unknown: BTreeSet::new(),
            secrets_unresolved: JMap::default(),
            schemas: BTreeMap::new(),
            events: Events::default(),
            written: Vec::new(),
            skip_writer_rules: false,
            key_actors: BTreeMap::new(),
            lost_due: BTreeSet::new(),
            live_trees: BTreeMap::new(),
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
    /// Loads the state of `(tid, ak)` into the cache.
    pub fn load(&mut self, tid: &Tid, ak: &Ak) -> Result<()> {
        let k = (*tid, ak.clone());
        if self.core.states.contains_key(&k) {
            return Ok(());
        }
        let f = match self.txn.get_aspect(tid, ak)? {
            Some(u) if state::is_paged(&u.state) => {
                let (f, idx) = state::load_paged(&mut self.txn, tid, ak, &u.state)?;
                self.core.pages.insert(k.clone(), idx);
                Some(f)
            }
            Some(u) if !u.state.is_empty() => Some(state::decode(&u.state)?),
            _ => None,
        };
        self.core.states.insert(k, f);
        Ok(())
    }

    pub fn state(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<&Fragment>> {
        self.load(tid, ak)?;
        Ok(self.core.states.get(&(*tid, ak.clone())).and_then(Option::as_ref))
    }

    /// Writes a state (keeping the unit's undo buffer unless `clear_undo`).
    pub fn set_state(&mut self, tid: &Tid, ak: &Ak, f: Option<Fragment>, shred: Shred, clear_undo: bool) -> Result<()> {
        self.core.touch();
        if osis_schema::core_types::is_membership_class(ak.as_str()) {
            self.core.membership_changed();
        }
        self.core.written.push((*tid, ak.clone()));
        let mut unit = self.txn.get_aspect(tid, ak)?.unwrap_or_default();
        let (bytes, idx) = state::write_full(&mut self.txn, tid, ak, f.as_ref(), state::is_paged(&unit.state))?;
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

    /// Writes a state a join changed: `touch` (`state::touch_of` the delta) says what it
    /// changed. A paged state rewrites only those pages (and its skeleton if needed); anything
    /// else is written whole. The caller has noted the state as written (`Core::written`).
    pub fn set_state_touched(&mut self, tid: &Tid, ak: &Ak, f: Option<Fragment>, touch: &state::Touch, shred: Shred) -> Result<()> {
        if osis_schema::core_types::is_membership_class(ak.as_str()) {
            self.core.membership_changed();
        }
        let k = (*tid, ak.clone());
        if let (Some(st), Some(idx), Some(touch)) = (&f, self.core.pages.get_mut(&k), touch)
            && let Some(unit_state) = state::write_touched(&mut self.txn, idx, tid, ak, st, touch, shred)?
        {
            if let Some(s) = unit_state {
                let mut unit = self.txn.get_aspect(tid, ak)?.unwrap_or_default();
                unit.state = s;
                self.txn.put_aspect(tid, ak, &unit, shred)?;
            }
            self.core.states.insert(k, f);
            return Ok(());
        }
        self.set_state(tid, ak, f, shred, false)
    }

    pub fn unit(&mut self, tid: &Tid, ak: &Ak) -> Result<AspectUnit> {
        Ok(self.txn.get_aspect(tid, ak)?.unwrap_or_default())
    }

    pub fn put_commit(&mut self, id: &CommitId, blob: &CommitBlob, meta: &Meta, shred: Shred) -> Result<()> {
        let mut w = Wr::new().u8(1).u64(meta.received.0).u8(match meta.origin {
            Origin::Local => 0,
            Origin::Remote => 1,
        });
        w = w.u32(meta.dropped.len() as u32);
        for (a, d) in &meta.dropped {
            w = w.u32(*a as u32).u32(*d as u32);
        }
        let v = w.raw(&blob.encode()).take();
        self.txn.put_local(&records::commit_key(id), &v, shred)?;
        Ok(())
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
    let mut r = Rd::new(v);
    if r.u8()? != 1 {
        return Err(Error::Corrupt("commit record version"));
    }
    let received = WallMs(r.u64()?);
    let origin = if r.u8()? == 0 { Origin::Local } else { Origin::Remote };
    let n = r.u32()?;
    let mut dropped = BTreeSet::new();
    for _ in 0..n {
        dropped.insert((r.u32()? as usize, r.u32()? as usize));
    }
    let blob = CommitBlob::decode(r.rest()).map_err(|_| Error::Corrupt("commit blob"))?;
    Ok((received, origin, dropped, blob))
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
        e.run(|tx| Ok(tx.txn.put_local(records::SEED, &seed_bytes, Shred::No)?))?;
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
        let r = match self.store.transaction(&mut self.store_rng) {
            Ok(txn) => {
                let mut tx = Tx { txn, core: &mut self.core, rng: &mut *self.rng };
                match f(&mut tx) {
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
                self.core.commit_journal();
                self.core.events.flush();
                Ok(v)
            }
            Err(e) => {
                self.core.events.discard();
                self.core.rollback();
                Err(e)
            }
        }
    }

    /// Rebuilds every in-memory cache and index from the store (keeps identity, clock and
    /// subscribers).
    pub(crate) fn reload(&mut self) -> Result<()> {
        let id = Identity::from_seed(self.core.id.seed().clone());
        let mut fresh = Core::new(id, self.clock.clone());
        fresh.hlc = Hlc::new(self.clock.clone(), self.core.hlc.last());
        fresh.hlc.set_offset(self.core.hlc.offset());
        fresh.events = std::mem::take(&mut self.core.events);
        fresh.key_actors = std::mem::take(&mut self.core.key_actors);
        fresh.schemas = std::mem::take(&mut self.core.schemas);
        fresh.skip_writer_rules = self.core.skip_writer_rules;
        self.core = fresh;
        let txn = self.store.transaction(&mut self.store_rng)?;
        let mut tx = Tx { txn, core: &mut self.core, rng: &mut *self.rng };
        crate::apply::load(&mut tx)?;
        self.core.commit_journal();
        Ok(())
    }
}
