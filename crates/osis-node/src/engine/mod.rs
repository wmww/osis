//! The engine: one node's local state over its `Store` (notes/architecture.md §2: the node
//! talks to `Store` only). Synchronous, no I/O of its own, time from a `Clock`, randomness
//! injected. Every mutating call runs in one store transaction; engine events are sent after
//! it is durable. A failed transaction drops the in-memory caches, which reload from the store.

pub(crate) mod blobs;
pub(crate) mod clock;
pub(crate) mod large;
mod read;
pub(crate) mod records;
pub(crate) mod secrets;
pub(crate) mod state;
pub(crate) mod write;

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
use osis_perm::{MemoryHeldSet, Timelines};
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

/// Node-form ranges of one node on one aspect: lo -> (hi, commit).
pub(crate) type Ranges = BTreeMap<u64, (u64, CommitId)>;

/// A scan callback: key (without prefix), value.
type ScanFn<'f> = dyn FnMut(&[u8], Vec<u8>) -> Result<()> + 'f;

/// A decoded commit record: received, origin, dropped parts, blob.
pub(crate) type CommitRecord = (WallMs, Origin, BTreeSet<(usize, usize)>, CommitBlob);

/// In-memory state over the store: caches and indexes, rebuilt by `load`.
pub(crate) struct Core {
    pub id: Identity,
    pub hlc: Hlc,
    pub states: HashMap<(Tid, Ak), Option<Fragment>>,
    /// Page indexes of the cached states kept paged in the store.
    pub pages: HashMap<(Tid, Ak), state::PageIndex>,
    /// Perm inputs: applied membership commits, roster snapshots, `/created` records.
    pub held: MemoryHeldSet,
    pub timelines: Timelines,
    pub commits: BTreeMap<CommitId, Meta>,
    /// Commits with a part invalid here, per aspect (`Core::index_validity`), so a join finds the
    /// writes to strip in O(invalid parts), not O(history).
    pub invalid: BTreeMap<(Tid, Ak), BTreeSet<CommitId>>,
    /// Held deltas per aspect: (`ts`, commit).
    pub by_aspect: BTreeMap<(Tid, Ak), BTreeSet<(Ts, CommitId)>>,
    /// Node-form ranges per (tid, ak, node): lo -> (hi, commit).
    pub ranges: BTreeMap<(Tid, Ak, Tid), Ranges>,
    pub pending: BTreeMap<CommitId, Reason>,
    pub syncing: BTreeSet<Tid>,
    pub void: BTreeSet<CommitId>,
    /// Deltas whose value-carrying writes are held value-less (expired, purged).
    pub valueless: BTreeMap<(Tid, Ak), Vec<Owned>>,
    /// Actors with secrets of their own whose epochs this node holds.
    pub secrets: BTreeMap<Tid, ActorEpochs>,
    /// Things known to have secrets of their own (a `/keys` with keysets).
    pub own_keys: BTreeSet<Tid>,
    /// `/was` index: t -> things whose `/was` reads t.
    pub was: BTreeMap<Tid, BTreeSet<Tid>>,
    pub moved: BTreeMap<Tid, Tid>,
    /// `/group` of each group thing: (items, subgroups).
    pub group_defs: BTreeMap<Tid, (BTreeSet<Tid>, BTreeSet<Tid>)>,
    /// `/groups`: thing -> groups containing it, transitively.
    pub groups: BTreeMap<Tid, BTreeSet<Tid>>,
    /// Keyed `/members` entries seen: (target, entry dot) -> (member, created value).
    pub member_keys: BTreeMap<(Tid, Dot), (Tid, Option<osis_core::Value>)>,
    /// Membership commits whose removed keys are not known yet.
    pub unresolved: BTreeSet<CommitId>,
    /// Box keys of keyed `/secrets` entries: (actor, entry dot) -> key.
    pub box_keys: BTreeMap<(Tid, Dot), osis_core::Value>,
    /// The earliest noted commit boxing an epoch or writing its keyset: (actor, role, epoch) ->
    /// (`ts`, author node, actor acted for). What introduced the epoch (`rotation`).
    pub epoch_intro: BTreeMap<(Tid, osis_core::Role, osis_crypto::Epoch), (Ts, Tid, Tid)>,
    /// The newest noted commit writing a box: (actor, box key) -> its `ts`.
    pub box_written: BTreeMap<(Tid, osis_schema::core_types::BoxKey), Ts>,
    /// `rotation::departures` per actor with the time it holds until (an edge's `until`, a
    /// write's future `ts`); cleared by `membership_changed`. Not backed up: a rollback clears it.
    pub departures: BTreeMap<Tid, (Vec<osis_keys::Departure>, Option<WallMs>)>,
    /// `/secrets` writes of applied commits waiting for the keys of the boxes they remove.
    pub secrets_unresolved: BTreeMap<(CommitId, usize), crate::apply::keys::Unresolved>,
    /// Roles `/secrets` and `/keys` deltas need (by commit and aspect index).
    pub rotation_role: BTreeMap<(CommitId, usize), osis_core::Role>,
    /// `/secrets` parts of membership commits that write beyond their grantees' boxes (an invite
    /// grant may carry only those, spec/permissions.md §2).
    pub grant_overreach: BTreeSet<(CommitId, usize)>,
    /// Schemas of local writes (typed views for undo).
    pub schemas: BTreeMap<osis_core::SchemaId, Arc<osis_schema::Schema>>,
    pub events: Events,
    /// The indexes as they were before the running transaction first changed them.
    pub backup: Option<Box<Backup>>,
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
    /// a state (`touch`, `rollback`).
    pub live_trees: BTreeMap<Tid, Option<BTreeSet<osis_core::BlobId>>>,
}

/// Index fields of `Core` saved for a rollback (states roll back by eviction, timelines by
/// re-evaluating the restored held set).
pub(crate) struct Backup {
    held: MemoryHeldSet,
    commits: BTreeMap<CommitId, Meta>,
    invalid: BTreeMap<(Tid, Ak), BTreeSet<CommitId>>,
    by_aspect: BTreeMap<(Tid, Ak), BTreeSet<(Ts, CommitId)>>,
    ranges: BTreeMap<(Tid, Ak, Tid), Ranges>,
    pending: BTreeMap<CommitId, Reason>,
    syncing: BTreeSet<Tid>,
    void: BTreeSet<CommitId>,
    valueless: BTreeMap<(Tid, Ak), Vec<Owned>>,
    secrets: BTreeMap<Tid, ActorEpochs>,
    own_keys: BTreeSet<Tid>,
    was: BTreeMap<Tid, BTreeSet<Tid>>,
    moved: BTreeMap<Tid, Tid>,
    group_defs: BTreeMap<Tid, (BTreeSet<Tid>, BTreeSet<Tid>)>,
    groups: BTreeMap<Tid, BTreeSet<Tid>>,
    member_keys: BTreeMap<(Tid, Dot), (Tid, Option<osis_core::Value>)>,
    unresolved: BTreeSet<CommitId>,
    rotation_role: BTreeMap<(CommitId, usize), osis_core::Role>,
    grant_overreach: BTreeSet<(CommitId, usize)>,
    box_keys: BTreeMap<(Tid, Dot), osis_core::Value>,
    epoch_intro: BTreeMap<(Tid, osis_core::Role, osis_crypto::Epoch), (Ts, Tid, Tid)>,
    box_written: BTreeMap<(Tid, osis_schema::core_types::BoxKey), Ts>,
    secrets_unresolved: BTreeMap<(CommitId, usize), crate::apply::keys::Unresolved>,
}

impl Core {
    /// Drops what is derived from rosters, `/secrets` and held epochs (the departures cache):
    /// called wherever those change.
    pub fn membership_changed(&mut self) {
        self.departures.clear();
    }

    /// Re-evaluates the timelines over the held set.
    pub fn update_timelines(&mut self) {
        self.timelines.update(&self.held);
        self.membership_changed();
    }

    /// Saves the indexes before the running transaction's first change to them.
    pub fn touch(&mut self) {
        self.live_trees.clear();
        if self.backup.is_some() {
            return;
        }
        self.backup = Some(Box::new(Backup {
            held: self.held.clone(),
            commits: self.commits.clone(),
            invalid: self.invalid.clone(),
            by_aspect: self.by_aspect.clone(),
            ranges: self.ranges.clone(),
            pending: self.pending.clone(),
            syncing: self.syncing.clone(),
            void: self.void.clone(),
            valueless: self.valueless.clone(),
            secrets: self.secrets.clone(),
            own_keys: self.own_keys.clone(),
            was: self.was.clone(),
            moved: self.moved.clone(),
            group_defs: self.group_defs.clone(),
            groups: self.groups.clone(),
            member_keys: self.member_keys.clone(),
            unresolved: self.unresolved.clone(),
            rotation_role: self.rotation_role.clone(),
            grant_overreach: self.grant_overreach.clone(),
            box_keys: self.box_keys.clone(),
            epoch_intro: self.epoch_intro.clone(),
            box_written: self.box_written.clone(),
            secrets_unresolved: self.secrets_unresolved.clone(),
        }));
    }

    /// Undoes the aborted transaction's changes to the caches.
    fn rollback(&mut self) {
        self.live_trees.clear();
        self.membership_changed();
        for k in std::mem::take(&mut self.written) {
            self.states.remove(&k);
            self.pages.remove(&k);
        }
        if let Some(b) = self.backup.take() {
            let b = *b;
            self.held = b.held;
            self.commits = b.commits;
            self.invalid = b.invalid;
            self.by_aspect = b.by_aspect;
            self.ranges = b.ranges;
            self.pending = b.pending;
            self.syncing = b.syncing;
            self.void = b.void;
            self.valueless = b.valueless;
            self.secrets = b.secrets;
            self.own_keys = b.own_keys;
            self.was = b.was;
            self.moved = b.moved;
            self.group_defs = b.group_defs;
            self.groups = b.groups;
            self.member_keys = b.member_keys;
            self.unresolved = b.unresolved;
            self.rotation_role = b.rotation_role;
            self.grant_overreach = b.grant_overreach;
            self.box_keys = b.box_keys;
            self.epoch_intro = b.epoch_intro;
            self.box_written = b.box_written;
            self.secrets_unresolved = b.secrets_unresolved;
            self.timelines.update(&self.held);
        }
    }

    fn new(id: Identity, clock: Arc<dyn Clock>) -> Core {
        Core {
            id,
            hlc: Hlc::new(clock, Ts::default()),
            states: HashMap::new(),
            pages: HashMap::new(),
            held: MemoryHeldSet::new(),
            timelines: Timelines::new(),
            commits: BTreeMap::new(),
            invalid: BTreeMap::new(),
            by_aspect: BTreeMap::new(),
            ranges: BTreeMap::new(),
            pending: BTreeMap::new(),
            syncing: BTreeSet::new(),
            void: BTreeSet::new(),
            valueless: BTreeMap::new(),
            secrets: BTreeMap::new(),
            own_keys: BTreeSet::new(),
            was: BTreeMap::new(),
            moved: BTreeMap::new(),
            group_defs: BTreeMap::new(),
            groups: BTreeMap::new(),
            member_keys: BTreeMap::new(),
            unresolved: BTreeSet::new(),
            rotation_role: BTreeMap::new(),
            grant_overreach: BTreeSet::new(),
            box_keys: BTreeMap::new(),
            epoch_intro: BTreeMap::new(),
            box_written: BTreeMap::new(),
            departures: BTreeMap::new(),
            secrets_unresolved: BTreeMap::new(),
            schemas: BTreeMap::new(),
            events: Events::default(),
            backup: None,
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
                if let Some(s) = self.invalid.get_mut(&k) {
                    s.remove(id);
                    if s.is_empty() {
                        self.invalid.remove(&k);
                    }
                }
            } else {
                self.invalid.entry(k).or_default().insert(*id);
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
        if let (Some(st), Some(idx)) = (&f, self.core.pages.get_mut(&k))
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
                self.core.backup = None;
                self.core.written.clear();
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
        crate::apply::load(&mut tx)
    }
}
