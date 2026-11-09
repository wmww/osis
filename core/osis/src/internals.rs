//! Engine access for the CLI's `inspect`, the simulator and test harnesses: not app API, so the
//! whole module is hidden from the docs and `Osis`'s own documentation stays app-only.

use crate::Osis;
use osis_node::sync::{Action, Event, SyncEngine};
use osis_node::Engine;

pub use crate::commits::COMMIT_PAGE;
pub use crate::net::ManualNet;
pub use crate::account::OFFER_LIFETIME_MS;
pub use crate::port::client::{own_uid, socket_dir, socket_path, socket_path_under};
pub use crate::port::{COMMIT_DIRTY_BYTES, COMMIT_SEND, MAX_SCHEMA_BYTES, PUSH_BYTES, STREAM_CHUNK, WRITE_NONCES};
pub use crate::value_type::of_schema;
pub use osis_base::{Clock, CommitId as RawCommitId, CreationRecord, LabelId, ManualClock, Ts};
pub use osis_node as node;
pub use osis_node::sync::MAX_CONNS_PER_CLIENT;
pub use osis_schema as schema;
pub use osis_schema::core_types;
pub use osis_transport::{InProcess, MemUdp};

/// `group.0`'s field of items, for path reads and writes of it (spec/data-model.md §8).
pub const GROUP_ITEMS: osis_schema::FieldId = osis_schema::FieldId(0);
/// `group.0`'s field of subgroups.
pub const GROUP_SUBGROUPS: osis_schema::FieldId = osis_schema::FieldId(1);

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

/// The label an admission id stands for.
pub fn label_of(a: &crate::SyncId) -> LabelId {
    a.0
}

/// Sets a host limit by name, `ServingPolicy`'s or one it does not show (`--policy`, tests). `Err` on a
/// name or value the host cannot run by.
pub fn host_limit(p: &mut crate::ServingPolicy, name: &str, n: u64) -> Result<(), String> {
    p.set(name, n)
}

/// The host limits set that `ServingPolicy` does not show, by name.
pub fn host_limits_unshown(p: &crate::ServingPolicy) -> std::collections::BTreeMap<String, u64> {
    p.tuning.known.clone()
}

/// Writes a `KeepAlive` has made.
pub fn kept_writes(k: &crate::KeepAlive) -> u64 {
    k.writes()
}

/// A joining node's node tid, before it has finished.
pub fn joining_node(j: &crate::Joining) -> osis_base::Tid {
    j.node()
}

/// What tests measure of a `MemStore`.
pub trait MemStoreMeasures {
    /// The bytes the node's store holds.
    fn held_bytes(&self) -> u64;
    /// Rows in the store now.
    fn rows(&self) -> usize;
    /// The bytes held in rows, and in blobs with their number.
    fn held_split(&self) -> (u64, u64, u64);
    /// An independent copy of the store as it is now, as a node backup takes it (the host store
    /// left out): opening it later is a restore.
    fn backup(&self) -> crate::MemStore;
}

impl MemStoreMeasures for crate::MemStore {
    fn held_bytes(&self) -> u64 {
        crate::MemStore::held_bytes(self)
    }
    fn rows(&self) -> usize {
        crate::MemStore::rows(self)
    }
    fn held_split(&self) -> (u64, u64, u64) {
        crate::MemStore::held_split(self)
    }
    fn backup(&self) -> crate::MemStore {
        crate::MemStore::backup(self)
    }
}

/// What tests set on `AppConfig`.
#[derive(Clone, Default)]
pub struct Knobs {
    /// Wall clock in place of the system's.
    pub clock: Option<std::sync::Arc<dyn osis_base::Clock>>,
    /// Seed for a deterministic rng in place of OS randomness.
    pub seed: Option<u64>,
    /// In place of `CONNECTION_WAIT`.
    pub connection_wait: Option<std::time::Duration>,
    /// In-process endpoints in place of QUIC, for every `mem://` dial and listener.
    pub transport: Option<InProcess>,
    /// This node's host on an in-process NAT net (`Net::run_on_tokio`), for `peer://`: without it
    /// `peer://` is unknown to a node with `transport`.
    pub host: Option<MemUdp>,
    /// Called by a text session's save between taking its snapshot and committing it.
    pub text_save: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
}

/// How `status` folds labels into groups (tests).
pub fn groups_of_labels(labels: &[osis_node::sync::LabelStatus]) -> std::collections::BTreeMap<osis_base::Tid, crate::GroupSync> {
    crate::share::groups_of_labels(labels)
}

/// The hooks on `Osis` (`use osis::internals::Internals;`). Each panics on a thin client
/// (`Osis::connect`): its engine is a stand-in, never the node's.
pub trait Internals {
    /// Runs `f` on the engine under the node lock, then queues its events for the
    /// dispatcher.
    fn engine<R>(&self, f: impl FnOnce(&mut Engine) -> R) -> R;
    /// Runs `f` on the sync engine; its actions are carried out.
    fn sync_engine<R>(&self, f: impl FnOnce(&mut SyncEngine) -> R) -> R;
    /// Calls waiting for another node right now (a dropped future leaves none).
    fn waiting(&self) -> usize;
    /// `wait_synced` holding no handle, as the client port runs it.
    fn wait_synced_no_handle(&self, scope: crate::SyncScope) -> std::pin::Pin<Box<dyn std::future::Future<Output = crate::Result<()>> + Send>>;
    /// With `Runtime::Manual`: the network actions queued so far (the harness carries them).
    fn take_actions(&self) -> Vec<Action>;
    /// With `Runtime::Manual`: feeds a network event.
    fn feed(&self, ev: Event);
    /// Live dispatcher registrations: this process's watches and the client port's
    /// subscriptions it serves.
    fn watches(&self) -> usize;
    /// A handle acting as `actor`, as the client port serves a thin client's session.
    fn acting_as(&self, actor: osis_base::Tid) -> Osis;
    /// The port worker's next job panics: before running (`false`), or after a Call ran and
    /// before its reply (`true`, the reply is lost).
    fn port_panic_next(&self, after_call: bool);
    /// The sync driver task panics at its next control (inside an engine call, under the lock).
    fn panic_driver(&self);
    /// On a thin client (the one hook that wants one): its connection thread panics.
    fn panic_client_thread(&self);
    /// Pads the next pairing reply the port sends by `n` bytes.
    fn port_pad_pair_reply(&self, n: usize);
    /// Runs `f` between each local write's source decision and its lock.
    fn after_source(&self, f: Box<dyn Fn() + Send>);
    /// Sets a group source with nothing else `group_source` does.
    fn set_source(&self, group: osis_base::Tid, to: Option<crate::Address>);
    /// Serves clients at the unix socket `path` (`Osis::listen_socket` picks the store's).
    fn listen_socket_at(&self, path: &std::path::Path) -> crate::Result<()>;
}

impl Internals for Osis {
    fn engine<R>(&self, f: impl FnOnce(&mut Engine) -> R) -> R {
        here(self);
        Osis::engine(self, f)
    }
    fn sync_engine<R>(&self, f: impl FnOnce(&mut SyncEngine) -> R) -> R {
        here(self);
        self.locked(|l| f(&mut l.sync))
    }
    fn waiting(&self) -> usize {
        here(self);
        self.locked(|l| l.waiters.len())
    }
    fn wait_synced_no_handle(&self, scope: crate::SyncScope) -> std::pin::Pin<Box<dyn std::future::Future<Output = crate::Result<()>> + Send>> {
        Box::pin(self.wait_synced_pending(scope))
    }

    fn take_actions(&self) -> Vec<Action> {
        here(self);
        self.inner.net.take()
    }
    fn feed(&self, ev: Event) {
        here(self);
        self.handled(|l| l.sync.handle(ev));
    }
    fn watches(&self) -> usize {
        here(self);
        self.inner.dispatch.registrations()
    }
    fn acting_as(&self, actor: osis_base::Tid) -> Osis {
        here(self);
        self.act_as(actor)
    }
    fn panic_driver(&self) {
        here(self);
        self.inner.net.panic_driver();
    }
    fn panic_client_thread(&self) {
        Osis::panic_client_thread(self);
    }
    fn port_pad_pair_reply(&self, n: usize) {
        self.inner.port.pad_pair_reply.store(n, std::sync::atomic::Ordering::Release);
    }

    fn port_panic_next(&self, after_call: bool) {
        let p = &self.inner.port;
        (if after_call { &p.panic_after_call } else { &p.panic_next }).store(true, std::sync::atomic::Ordering::Release);
    }
    fn listen_socket_at(&self, path: &std::path::Path) -> crate::Result<()> {
        Osis::listen_socket_at(self, path)
    }
    fn after_source(&self, f: Box<dyn Fn() + Send>) {
        *crate::watch::lock(&self.inner.port.after_source) = Some(f);
    }
    fn set_source(&self, group: osis_base::Tid, to: Option<crate::Address>) {
        self.inner.routing.store(true, std::sync::atomic::Ordering::Release);
        self.locked(|l| match to {
            Some(a) => l.group_sources.insert(group, a),
            None => l.group_sources.remove(&group),
        });
        self.locked(|l| l.show_sources());
    }
}

/// Panics on a thin client (`Internals` reads this process's engine).
fn here(db: &Osis) {
    assert!(db.has_store(), "Internals on a thin client: Unsupported (its engine is a stand-in)");
}

/// A store, its hosts and its config in one value, for test harnesses that build all three in one
/// helper: the fields of `Config` read through it.
#[derive(Clone)]
pub struct Opening {
    pub store: crate::Store,
    pub hosts: Vec<crate::Address>,
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
        Opening { store, hosts: Vec::new(), cfg: crate::Config { lan: crate::Lan::Off, ..crate::Config::default() } }
    }

    pub fn memory() -> Opening {
        Opening::at(crate::Store::Memory(crate::MemStore::new()))
    }

    pub fn dir(path: impl Into<std::path::PathBuf>) -> Opening {
        Opening::at(crate::Store::Dir(path.into()))
    }

}

pub fn create(o: Opening) -> crate::Result<Osis> {
    Osis::create(o.store, &o.hosts, o.cfg)
}

pub fn open(o: Opening) -> crate::Result<Osis> {
    Osis::open(o.store, o.cfg)
}

pub fn pair(o: Opening, offer: &crate::PairOffer) -> crate::Result<crate::Joining> {
    Osis::pair(o.store, &o.hosts, offer, o.cfg)
}

pub async fn connect_socket(socket: &std::path::Path, o: Opening) -> crate::Result<Osis> {
    Osis::connect_socket_at(socket, o.cfg.app).await
}

pub async fn connect(addr: &crate::Address, secret: &crate::ClientSecret, o: Opening) -> crate::Result<Osis> {
    connect_all(&[crate::NodeLogin { addr: addr.clone(), secret: secret.clone() }], o).await
}

pub async fn connect_all(logins: &[crate::NodeLogin], o: Opening) -> crate::Result<Osis> {
    Osis::connect(logins, o.cfg.app).await
}
