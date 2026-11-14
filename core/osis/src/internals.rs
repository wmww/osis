//! Engine access for the CLI's `inspect`, the simulator and test harnesses: not app API, so the
//! whole module is hidden from the docs and `Osis`'s own documentation stays app-only.

use crate::Osis;
use osis_engine::Engine;

pub use crate::backlinks::BACKLINK_PAGE;
pub use crate::commits::COMMIT_PAGE;
pub use crate::account::OFFER_LIFETIME_MS;
pub use crate::value_type::of_schema;
pub use osis_base::{Clock, CommitId as RawCommitId, CreationRecord, SyncId, ManualClock, Ts};
pub use osis_base::costs;
pub use osis_engine as engine;
pub use osis_schema as schema;
pub use osis_schema::core_types;
pub use osis_store::{Fault, Faults};
pub use crate::net::{MANUAL_CAP, MANUAL_HORIZON_MS, ManualNet};

/// `group.0`'s field of items, for path reads and writes of it (spec/data-model.md §8).
pub const GROUP_ITEMS: osis_schema::FieldId = osis_schema::FieldId(0);
/// `group.0`'s field of subgroups.
pub const GROUP_SUBGROUPS: osis_schema::FieldId = osis_schema::FieldId(1);

/// What a `ReadSet` listens to (its addresses, e.g. `value {tid} {ak} Path([])`, `aspects {tid}`)
/// and how often the last pass read each: a harness finds a read made twice by one node.
pub fn read_counts(set: &crate::ReadSet) -> Vec<(String, u32)> {
    set.counts()
}

/// What a commit's id holds, as a test asks.
pub trait CommitRaw {
    /// The engine's id of the commit it names.
    fn raw(&self) -> RawCommitId;
}

impl CommitRaw for crate::CommitId {
    fn raw(&self) -> RawCommitId {
        self.0
    }
}

/// The exact order value behind a public time.
pub trait Exact {
    fn ts(&self) -> Ts;
}

impl Exact for crate::Stamp {
    fn ts(&self) -> Ts {
        self.ts
    }
}

impl Exact for crate::ThingStamp {
    fn ts(&self) -> Ts {
        self.ts
    }
}

impl Exact for crate::Commit {
    fn ts(&self) -> Ts {
        self.stamp.ts
    }
}

impl Exact for crate::CommitPos {
    fn ts(&self) -> Ts {
        self.0.ts
    }
}

/// A stream's chunks fetched so far, and the most bytes of chunk and tree path it held at once.
pub fn stream_work(s: &crate::ValueStream) -> (u64, usize) {
    s.work()
}

/// A store in memory whose engine store (rows and key root) fails as `faults` plans.
pub fn faulty_store(faults: Faults) -> crate::MemStore {
    crate::MemStore { backend: osis_store::MemoryBackend::with_faults(faults.clone()), root: osis_store::MemoryRoot::with_faults(faults), ..Default::default() }
}

/// What tests measure of a `MemStore`.
pub trait MemStoreMeasures {
    /// The bytes the node's stores hold, the engine's and its ciphertext store's.
    fn held_bytes(&self) -> u64;
    /// Rows in the engine's store now.
    fn rows(&self) -> usize;
    /// The bytes held in rows, and in blobs with their number, over both stores.
    fn held_split(&self) -> (u64, u64, u64);
    /// An independent copy of the store as it is now, as a node backup takes it: opening it
    /// later is a restore.
    fn backup(&self) -> crate::MemStore;
}

impl MemStoreMeasures for crate::MemStore {
    fn held_bytes(&self) -> u64 {
        self.backend.held_bytes() + self.blobs.held_bytes()
    }
    fn rows(&self) -> usize {
        self.backend.dump().len()
    }
    fn held_split(&self) -> (u64, u64, u64) {
        let (a, b) = (self.backend.held_split(), self.blobs.held_split());
        (a.0 + b.0, a.1 + b.1, a.2 + b.2)
    }
    fn backup(&self) -> crate::MemStore {
        crate::MemStore { backend: self.backend.copy(), root: self.root.copy(), opens: self.opens.clone(), blobs: self.blobs.copy(), blobs_root: self.blobs_root.copy() }
    }
}

/// What tests set on `AppConfig`.
#[derive(Clone, Default)]
pub struct Knobs {
    /// Wall clock in place of the system's.
    pub clock: Option<std::sync::Arc<dyn osis_base::Clock>>,
    /// Seed for a deterministic rng in place of OS randomness.
    pub seed: Option<u64>,
    /// Called by a text session's save between taking its snapshot and committing it.
    pub text_save: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
    /// A test network in place of the transports: the node joins it and nothing else.
    pub net: Option<crate::net::ManualNet>,
    /// An in-process transport (`mem://`) beside the product's, under a runtime.
    pub transport: Option<osis_transport::InProcess>,
}

/// The hooks on `Osis` (`use osis::internals::Internals;`).
pub trait Internals {
    /// Runs `f` on the engine under the node lock, then queues its events for the
    /// dispatcher.
    fn engine<R>(&self, f: impl FnOnce(&mut Engine) -> R) -> R;
    /// Live dispatcher registrations: this process's watches.
    fn watches(&self) -> usize;
    /// A handle acting as `actor`, as the client port serves a thin client's session.
    fn acting_as(&self, actor: osis_base::Tid) -> Osis;
}

impl Internals for Osis {
    fn engine<R>(&self, f: impl FnOnce(&mut Engine) -> R) -> R {
        crate::handle::ReadOnly::engine(self, f)
    }
    fn watches(&self) -> usize {
        self.inner.dispatch.registrations()
    }
    fn acting_as(&self, actor: osis_base::Tid) -> Osis {
        self.act_as(actor)
    }
}

/// A store and its config in one value, for test harnesses that build all three in one
/// helper: the fields of `Config` read through it.
#[derive(Clone)]
pub struct Opening {
    pub store: crate::Store,
    pub cfg: crate::Config,
}

impl std::ops::Deref for Opening {
    type Target = crate::Config;
    fn deref(&self) -> &crate::Config {
        &self.cfg
    }
}

impl std::ops::DerefMut for Opening {
    fn deref_mut(&mut self) -> &mut crate::Config {
        &mut self.cfg
    }
}

impl Opening {
    pub fn at(store: crate::Store) -> Opening {
        // no harness announces on the machine's real network unless it asks to
        Opening { store, cfg: crate::Config { lan: crate::Lan::Off, ..crate::Config::default() } }
    }

    pub fn memory() -> Opening {
        Opening::at(crate::Store::Memory(crate::MemStore::new()))
    }

    pub fn dir(path: impl Into<std::path::PathBuf>) -> Opening {
        Opening::at(crate::Store::Dir(path.into()))
    }

}

pub fn create(o: Opening) -> crate::Result<Osis> {
    Osis::create(o.store, o.cfg)
}

pub fn open(o: Opening) -> crate::Result<Osis> {
    Osis::open(o.store, o.cfg)
}

pub fn pair(o: Opening, offer: &crate::PairOffer) -> crate::Result<crate::Joining> {
    Osis::pair(o.store, offer, o.cfg)
}

/// The client port's answers to `msgs` sent on connection `conn` (`main`: over the unix
/// transport), as the node gives them, with no transport between.
pub fn port_answers(db: &Osis, conn: u64, main: bool, msgs: Vec<osis_proto::Msg>) -> Vec<osis_proto::Msg> {
    crate::port::answer_all(db, osis_sync::ConnId(conn), main, msgs)
}

pub use crate::port::method as port_method;
pub use osis_proto as proto;
pub use osis_crypto::Secret32;
pub use osis_label as label;
