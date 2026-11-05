//! Engine access for the CLI's `inspect`, the simulator and test harnesses: not app API, so the
//! whole module is hidden from the docs and `Osis`'s own documentation stays app-only.

use crate::Osis;
use osis_node::sync::{Action, Event, SyncEngine};
use osis_node::Engine;

pub use crate::net::ManualNet;
pub use osis_node as node;

/// What tests set on `Config` and `ClientConfig`.
#[derive(Clone, Default)]
pub struct Knobs {
    /// Wall clock in place of the system's.
    pub clock: Option<std::sync::Arc<dyn osis_base::Clock>>,
    /// Seed for a deterministic rng in place of OS randomness.
    pub seed: Option<u64>,
}

/// The hooks on `Osis` (`use osis::internals::Internals;`). Each panics on a thin client
/// (`Osis::connect`): its engine is a stand-in, never the node's.
pub trait Internals {
    /// Runs `f` on the engine under the database lock, then queues its events for the
    /// dispatcher.
    fn engine<R>(&self, f: impl FnOnce(&mut Engine) -> R) -> R;
    /// Runs `f` on the sync engine; its actions are carried out.
    fn sync_engine<R>(&self, f: impl FnOnce(&mut SyncEngine) -> R) -> R;
    /// Calls waiting for another node right now (a dropped future leaves none).
    fn waiting(&self) -> usize;
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
    /// Runs `f` between each local write's route and its lock.
    fn after_route(&self, f: Box<dyn Fn() + Send>);
    /// Sets a route with nothing else `group_source` does.
    fn set_route(&self, group: osis_base::Tid, to: Option<crate::HostAddr>);
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
    fn after_route(&self, f: Box<dyn Fn() + Send>) {
        *crate::watch::lock(&self.inner.port.after_route) = Some(f);
    }
    fn set_route(&self, group: osis_base::Tid, to: Option<crate::HostAddr>) {
        self.inner.routing.store(true, std::sync::atomic::Ordering::Release);
        self.locked(|l| match to {
            Some(a) => l.routes.insert(group, a),
            None => l.routes.remove(&group),
        });
        self.locked(|l| l.show_routes());
    }
}

/// Panics on a thin client (`Internals` reads this process's engine).
fn here(db: &Osis) {
    assert!(db.has_store(), "Internals on a thin client: Unsupported (its engine is a stand-in)");
}

/// How long test harnesses wait when a test names no time of its own.
pub const WAIT: std::time::Duration = std::time::Duration::from_secs(60);
/// The same, for catching up before a role is lowered.
pub const PRESYNC: std::time::Duration = std::time::Duration::from_secs(30);

/// A store, its hosts and its config in one value, for test harnesses that build all three in one
/// helper: the fields of `Config` read through it. A client takes its transport, limits and
/// dispatcher from it, and `wait_timeout` is what its connection and a `restore` wait.
#[derive(Clone)]
pub struct Opening {
    pub store: crate::Store,
    pub hosts: Vec<crate::HostAddr>,
    pub wait_timeout: std::time::Duration,
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
        Opening { store, hosts: Vec::new(), wait_timeout: WAIT, cfg: crate::Config::default() }
    }

    pub fn memory() -> Opening {
        Opening::at(crate::Store::Memory(crate::MemStore::new()))
    }

    pub fn dir(path: impl Into<std::path::PathBuf>) -> Opening {
        Opening::at(crate::Store::Dir(path.into()))
    }

    fn client(self) -> crate::ClientConfig {
        let c = self.cfg;
        crate::ClientConfig { materialize_limit: c.materialize_limit, transport: c.transport, idle_commit: c.idle_commit, dispatch: c.dispatch, internals: c.internals }
    }
}

pub fn create(o: Opening) -> crate::Result<(Osis, Option<crate::RecoveryCard>)> {
    Osis::create(o.store, &o.hosts, o.cfg)
}

pub fn open(o: Opening) -> crate::Result<Osis> {
    Osis::open(o.store, o.cfg)
}

pub fn pair(o: Opening, offer: &crate::PairOffer) -> crate::Result<crate::Joining> {
    Osis::pair(o.store, &o.hosts, offer, o.cfg)
}

pub async fn restore(o: Opening, card: &crate::RecoveryCard) -> crate::Result<Osis> {
    Osis::restore(o.store, &o.hosts, card, o.wait_timeout, o.cfg).await
}

pub fn connect_socket(socket: &std::path::Path, o: Opening) -> crate::Result<Osis> {
    let t = o.wait_timeout;
    Osis::connect_socket(socket, t, o.client())
}

pub fn connect(addr: &crate::HostAddr, secret: &crate::ClientSecret, o: Opening) -> crate::Result<Osis> {
    connect_all(&[crate::NodeLogin { addr: addr.clone(), secret: secret.clone() }], o)
}

pub fn connect_all(logins: &[crate::NodeLogin], o: Opening) -> crate::Result<Osis> {
    let t = o.wait_timeout;
    Osis::connect(logins, t, o.client())
}
