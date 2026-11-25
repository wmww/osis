//! Engine access for the CLI's `inspect`, the simulator and test harnesses: not app API, so the
//! whole module is hidden from the docs and `Osis`'s own documentation stays app-only.

use crate::Osis;
use osis_engine::Engine;

pub use crate::commits::COMMIT_PAGE;
pub use osis_sync::types::FOLLOW_LINK_MS;
pub use crate::value_type::of_schema;
pub use osis_base::{Clock, CommitId as RawCommitId, CreationRecord, ManualClock, Ts};
pub use osis_base::costs;
pub use osis_engine as engine;
pub use osis_base as base;
pub use osis_crypto as crypto;
pub use osis_crdt as crdt;
pub use osis_schema as schema;
pub use osis_schema::core_types;
pub use osis_store::{Fault, Faults};
pub use crate::net::ManualNet;

/// What a `ReadSet` listens to (its addresses, e.g. `value {tid} {ak} Path([])`, `aspects {tid}`)
/// and how often the last pass read each: a harness finds a read made twice by one node.
pub fn read_counts(set: &crate::ReadSet) -> Vec<(String, u32)> {
    set.counts()
}

/// Hands `to` each sealed fire `from` owes on a thing `to` holds a read secret of, as sync's fire
/// step does between connected nodes (spec/sync-inbox.md §3): a harness carrying commits by hand
/// carries fires so, and a grant from outside reaches its holder as its `grant@~0` fire
/// (spec/sync-inbox.md §5 Grant from outside). Whether `to` refused any (the thing's setting, as `to`
/// holds it, keeps no such signal).
pub fn pass_fires(from: &Osis, to: &Osis) -> bool {
    let fired = |e: &mut Engine| e.fire_own().map_err(|e| e.to_string());
    let outs = from.engine(|e| {
        fired(e)?;
        let mut outs = Vec::new();
        for id in e.fires_owed() {
            outs.extend(e.sealed_fire(&id).map_err(|e| e.to_string())?);
        }
        Ok::<_, String>(outs)
    });
    let Ok(outs) = outs else { return true };
    to.engine(|e| {
        let mut refused = false;
        for o in outs {
            if !e.epochs(&o.thing).is_some_and(|k| k.read.holds_any()) {
                continue;
            }
            let opened = e.offer_fire(&o);
            refused |= !matches!(opened, Ok(o) if !matches!(o, osis_engine::sync::Opened::Bad));
        }
        refused | fired(e).is_err()
    })
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

/// The handle a `Write` writes through, for test helpers building on one.
pub trait WriteDb {
    fn db(&self) -> &Osis;
}

impl WriteDb for crate::Write<'_> {
    fn db(&self) -> &Osis {
        crate::Write::db(self)
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
    /// Rows in the engine's store now.
    fn rows(&self) -> usize;
    /// The bytes held in rows, and in blobs with their number, over both stores.
    fn held_split(&self) -> (u64, u64, u64);
}

impl MemStoreMeasures for crate::MemStore {
    fn rows(&self) -> usize {
        self.backend.dump().len()
    }
    fn held_split(&self) -> (u64, u64, u64) {
        let (a, b) = (self.backend.held_split(), self.blobs.held_split());
        (a.0 + b.0, a.1 + b.1, a.2 + b.2)
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
    /// A thin client's scratch node (`sources::scratch`): it dials its node's socket.
    pub(crate) thin: bool,
    /// The node neither listens for other nodes nor finds them on the local network: it syncs
    /// only with those it dials (`Config::dial`): a thin client's scratch node, and a test that
    /// serves its socket on a real runtime without opening a network port.
    pub no_listen: bool,
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
    /// Every address the driver listens at now, direct sync's dialable listener included
    /// (empty without a runtime).
    fn listening(&self) -> Vec<crate::Address>;
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
    fn listening(&self) -> Vec<crate::Address> {
        self.inner.net.listening().into_iter().map(crate::Address).collect()
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

/// The client port's answers to `msgs` sent on connection `conn` (`main`: over the unix
/// transport), as the node gives them, with no transport between.
pub fn port_answers(db: &Osis, conn: u64, main: bool, msgs: Vec<osis_proto::Msg>) -> Vec<osis_proto::Msg> {
    crate::port::answer_all(db, osis_sync::ConnId(conn), main, msgs)
}

/// The client port's sessions and nonce sessions (per identity and session id) `db` holds.
pub fn port_held(db: &Osis) -> (usize, usize) {
    db.locked(|l| l.port.held())
}

/// The rows that wait (`wait_synced`, `redeem`) the port holds for clients.
pub fn port_waits(db: &Osis) -> usize {
    db.locked(|l| l.port.waits())
}

pub use crate::port::method as port_method;
pub use osis_proto as proto;
pub use osis_crypto::Secret32;
pub use osis_blob as blob;

/// What the compile-time checks of key kinds and of `ReadOnly` (doc tests) share: a signal
/// `PING` and a value aspect `N`.
pub mod checks {
    static S: crate::generated::StaticSchema = crate::generated::StaticSchema::new("t.osis", "revision 1;\nsignal t:ping~0: int;\naspect t:n.0: int;\n");
    pub const PING: crate::Signal<i64> = crate::Signal::new("t:ping~0", &S);
    pub const N: crate::Aspect<i64> = crate::Aspect::new("t:n.0", &S);

    /// A node in memory and a thing it holds.
    pub fn node() -> crate::Result<(crate::Osis, crate::Tid)> {
        let db = crate::Osis::create(crate::Store::Memory(crate::MemStore::new()), crate::Config::default())?;
        let mut w = db.write();
        let t = w.create(db.node(), None)?;
        w.hold(db.node(), t)?;
        w.commit()?;
        Ok((db, t))
    }
}

/// The client socket's directory and path rules (`Osis::listen_socket`).
pub use crate::sources::{socket_dir, socket_path_under};
pub use osis_transport::unix::{MAX_PATH as SOCKET_MAX_PATH, own_uid};
