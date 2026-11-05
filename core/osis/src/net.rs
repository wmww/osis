//! Background sync (notes/api.md Design rules): the sync engine's network actions leave through
//! `Net`, a tokio driver (osis-node `sync::driver::run_shared`) over the handle's lock, or a queue
//! a test harness carries (`Runtime::Manual`). Futures of the calls that wait for another node
//! are runtime-agnostic: a `Waiter` checked after every change under the lock resolves a
//! `Pending` through a slot.

use crate::error::{Error, Result};
use crate::handle::WeakOsis;
use crate::share::Status;
use crate::watch::lock;
use osis_base::{Clock, Value};
use osis_node::sync::driver::{self, Control, Shared};
use osis_node::sync::{Action, SyncEngine};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use tokio::sync::mpsc;

/// Where background sync runs.
#[derive(Clone, Debug, Default)]
pub enum Runtime {
    /// No network: everything works locally; calls that wait for another node fail `Network`.
    #[default]
    None,
    /// The app's tokio runtime (multi-thread recommended: osis's work blocks its thread for a moment).
    Tokio(tokio::runtime::Handle),
    /// A small tokio runtime of osis's own.
    Own,
    /// A test harness carries the actions (`internals::Internals::take_actions`, `feed`) of
    /// every node opened with this registry.
    #[doc(hidden)]
    Manual(ManualNet),
}

/// The nodes a test harness drives (`Runtime::Manual`), in the order they started.
#[derive(Clone, Debug, Default)]
pub struct ManualNet(Arc<Mutex<Vec<WeakOsis>>>);

impl ManualNet {
    /// A new one, with no nodes.
    pub fn new() -> ManualNet {
        ManualNet::default()
    }

    /// The nodes still open, by start order (`None`: closed).
    pub fn dbs(&self) -> Vec<Option<crate::Osis>> {
        lock(&self.0).iter().map(|w| w.upgrade()).collect()
    }

    pub(crate) fn register(&self, db: WeakOsis) {
        lock(&self.0).push(db);
    }
}

pub(crate) enum Net {
    Off,
    Manual(Mutex<Vec<Action>>),
    /// `died`: why the driver task ended while the node was open (set under the engine
    /// lock, `driver_died`).
    Driver { ctl: mpsc::UnboundedSender<Control>, handle: tokio::runtime::Handle, stop: Mutex<Option<Stop>>, died: Mutex<Option<String>> },
}

/// Ends the driver's runtime use after the driver task ended. An engine call runs in
/// `block_in_place`, off the workers, so a runtime shutdown does not wait for it, and the task
/// polled on after it returns would find the runtime's timers gone (tokio panics). osis's own
/// runtime (`Runtime::Own`) is shut down by a thread that waits for the task's end; `close`
/// waits for that thread (`Net::ended`: every task of the runtime, the host's too, is gone, so
/// the host store is closed), on the app's runtime for the task's end, so the app may shut its
/// runtime down next.
pub(crate) struct Stop {
    own: Option<tokio::runtime::Runtime>,
    /// Disconnects when the driver task ends (or was never spawned).
    ended: Ended,
    /// The driver task holds this until it ends.
    task: Option<std::sync::mpsc::Sender<()>>,
    /// `Runtime::Own`: the stopping thread holds the sender until the runtime shut down.
    freed: Option<(std::sync::mpsc::Sender<()>, Ended)>,
}

impl Drop for Net {
    fn drop(&mut self) {
        let Net::Driver { ctl, stop, .. } = self else { return };
        // the driver ends now, not when its last timer fires
        let _ = ctl.send(Control::Shutdown);
        let Some(Stop { own: Some(rt), ended, freed, .. }) = lock(stop).take() else { return };
        // `close` waits until this drops: the runtime, with every task on it, is gone
        let freed = freed.map(|(tx, _)| tx);
        // this drop may run inside the driver's engine call: wait on another thread
        let job = Arc::new(Mutex::new(Some((rt, ended, freed))));
        let j = job.clone();
        let spawned = std::thread::Builder::new().name("osis-sync-stop".into()).spawn(move || {
            if let Some((rt, ended, _freed)) = lock(&j).take() {
                // bounded: a driver awaiting the network is not in an engine call (the node
                // is gone) and may be dropped
                let _ = lock(&ended).recv_timeout(STOP_WAIT);
                rt.shutdown_timeout(STOP_WAIT);
            }
        });
        if spawned.is_err()
            && let Some((rt, _, _)) = lock(&job).take()
        {
            // no thread to wait on: `close` returns before the tasks are gone
            rt.shutdown_background();
        }
    }
}

/// How long the stopping thread waits for the driver task to end, then for the workers and
/// blocking tasks of osis's own runtime.
const STOP_WAIT: Duration = Duration::from_secs(5);

/// Disconnects when the driver task ends.
pub(crate) type Ended = Arc<Mutex<std::sync::mpsc::Receiver<()>>>;

/// Waits until the driver is gone (`Net::ended`): the task ends at the `Shutdown` the closed
/// node's `Net` queued (it polls no timer while a control message waits, and runs no engine
/// call: the node is gone); on osis's own runtime the stopping thread then shuts it down.
pub(crate) fn wait_ended(ended: &Ended) {
    blocking(|| {
        let _ = lock(ended).recv();
    });
}

/// Runs `f`, which blocks; inside a multi-thread runtime in place, so that worker's tasks move
/// to others meanwhile.
pub(crate) fn blocking<R>(f: impl FnOnce() -> R) -> R {
    match tokio::runtime::Handle::try_current().map(|h| h.runtime_flavor()) {
        Ok(tokio::runtime::RuntimeFlavor::MultiThread) => tokio::task::block_in_place(f),
        _ => f(),
    }
}

impl Net {
    pub fn new(rt: &Runtime) -> Result<(Net, Option<mpsc::UnboundedReceiver<Control>>)> {
        let (handle, own) = match rt {
            Runtime::None => return Ok((Net::Off, None)),
            Runtime::Manual(_) => return Ok((Net::Manual(Mutex::new(Vec::new())), None)),
            Runtime::Tokio(h) => (h.clone(), None),
            Runtime::Own => {
                let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).thread_name("osis-sync").enable_all().build().map_err(|e| Error::Network(e.to_string()))?;
                (rt.handle().clone(), Some(rt))
            }
        };
        let (task, ended) = std::sync::mpsc::channel();
        let freed = own.is_some().then(|| {
            let (tx, rx) = std::sync::mpsc::channel();
            (tx, Arc::new(Mutex::new(rx)))
        });
        let (ctl, rx) = mpsc::unbounded_channel();
        Ok((Net::Driver { ctl, handle, stop: Mutex::new(Some(Stop { own, ended: Arc::new(Mutex::new(ended)), task: Some(task), freed })), died: Mutex::new(None) }, Some(rx)))
    }

    /// What disconnects once the driver is gone (`close` waits on it): on osis's own runtime,
    /// once that runtime shut down (the stopping thread is bounded: `STOP_WAIT` twice); on the
    /// app's multi-thread runtime, once the driver task ended. Not on a current-thread one: the
    /// driver runs only while the app drives that runtime (`close` waiting there could hang), and
    /// runs no engine call in `block_in_place` there, so shutting it down at any time is safe.
    pub fn ended(&self) -> Option<Ended> {
        let Net::Driver { stop, handle, .. } = self else { return None };
        let s = lock(stop);
        let s = s.as_ref()?;
        if let Some((_, freed)) = &s.freed {
            return Some(freed.clone());
        }
        (handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread).then(|| s.ended.clone())
    }

    /// Whether anything carries actions.
    pub fn online(&self) -> bool {
        !matches!(self, Net::Off)
    }

    /// Hands actions to the driver (called under the engine lock, so they keep their order).
    pub fn apply(&self, acts: Vec<Action>) {
        if acts.is_empty() {
            return;
        }
        match self {
            Net::Off => {}
            Net::Manual(q) => lock(q).extend(acts),
            Net::Driver { ctl, .. } => {
                let _ = ctl.send(Control::Apply(acts));
            }
        }
    }

    pub fn take(&self) -> Vec<Action> {
        match self {
            Net::Manual(q) => std::mem::take(&mut *lock(q)),
            _ => Vec::new(),
        }
    }

    /// Starts the driver task over one transport for every node it dials (`Multi`; what it serves
    /// for others stored beside the node). With `p2p` (`Config::direct_sync`) and a peer transport, it listens with the dialable secret
    /// (registered at `relays`) and publishes `reach.0`; with feature `lan` and QUIC it also runs
    /// the LAN loop. Without a peer transport no peer is dialed.
    pub fn spawn_driver(&self, rx: mpsc::UnboundedReceiver<Control>, store: crate::Store, cfg: &crate::Config, clock: Arc<dyn Clock>, db: WeakOsis) -> Result<()> {
        let Net::Driver { handle, ctl, stop, .. } = self else { return Ok(()) };
        let shared = OsisShared(db.clone(), store);
        let (transport, p2p, relays) = (cfg.app.internals.transport.clone(), cfg.direct_sync, cfg.relays.iter().map(ToString::to_string).collect::<Vec<String>>());
        let log: driver::Log = Arc::new(|m: &str| log_line(m));
        // the client port's unix socket (`Osis::listen_socket`)
        let mut multi = osis_transport::Multi { unix: Some(osis_transport::Unix), ..Default::default() };
        // where the dialable-key listener goes, and whether the LAN loop runs
        let (reach, lan): (Option<String>, bool) = match transport {
            Some(t) => {
                let url = format!("mem://{}-peer", t.name());
                multi.mem = Some(t);
                (Some(url), false)
            }
            None => {
                multi.quic = Some(osis_transport::Quic::new());
                #[cfg(feature = "iroh")]
                {
                    multi.iroh = Some(osis_transport::Iroh::new());
                    (Some(osis_transport::peer_url(&relays)), cfg!(feature = "lan"))
                }
                #[cfg(not(feature = "iroh"))]
                (None, false)
            }
        };
        let alive = lock(stop).as_mut().and_then(|s| s.task.take());
        handle.spawn(async move {
            let _alive = alive;
            Watched { f: Box::pin(driver::run_shared(shared, multi, Vec::new(), clock, rx, log)), db, done: false }.await;
        });
        match reach {
            Some(url) if p2p => {
                let _ = ctl.send(Control::Reach { url, relays, reply: None });
                if lan {
                    let _ = ctl.send(Control::Lan(driver::LanConfig::default()));
                }
            }
            // nothing dials `peer://`: co-readers are not dialed
            None => {
                let _ = ctl.send(Control::Call(Box::new(|s| s.set_peers(false))));
            }
            Some(_) => {}
        }
        Ok(())
    }

    /// Serves the client port on a listener at `url`:
    /// its sessions are clients of this node. `Network` without a runtime.
    pub fn listen(&self, url: String) -> Result<()> {
        let Net::Driver { ctl, .. } = self else { return Err(Error::Network("no runtime: the client port needs one (Config.runtime)".into())) };
        let (tx, rx) = tokio::sync::oneshot::channel();
        ctl.send(Control::Listen { url, reply: Some(tx) }).map_err(|_| self.stopped())?;
        match blocking(|| rx.blocking_recv()) {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(Error::Network(e)),
            Err(_) => Err(self.stopped()),
        }
    }

    /// Replaces the client listeners.
    pub fn client_listen(&self, urls: driver::ClientUrls) -> Result<Vec<osis_transport::Address>> {
        let Net::Driver { ctl, .. } = self else { return Err(Error::Network("no runtime: the client listener needs one (Config.runtime)".into())) };
        let (tx, rx) = tokio::sync::oneshot::channel();
        ctl.send(Control::ClientListen { urls, reply: tx }).map_err(|_| self.stopped())?;
        match blocking(|| rx.blocking_recv()) {
            Ok(r) => r.map_err(Error::Network),
            Err(_) => Err(self.stopped()),
        }
    }

    /// Why the driver is gone: how it died, else "sync stopped".
    fn stopped(&self) -> Error {
        self.died().unwrap_or_else(|| Error::Network("sync stopped".into()))
    }

    /// How the driver task died while the node was open (`driver_died`).
    pub fn died(&self) -> Option<Error> {
        let Net::Driver { died, .. } = self else { return None };
        lock(died).clone().map(Error::Network)
    }

    /// A test's way to panic the driver task: its next control panics inside an engine call.
    #[allow(clippy::panic)]
    pub fn panic_driver(&self) {
        if let Net::Driver { ctl, .. } = self {
            let _ = ctl.send(Control::Call(Box::new(|_| panic!("test: the sync driver panics"))));
        }
    }

    /// Runs `f` on the runtime after `d`; `false` (and `f` dropped) without one.
    pub fn after(&self, d: Duration, f: Box<dyn FnOnce() + Send>) -> bool {
        let Net::Driver { handle, .. } = self else { return false };
        handle.spawn(async move {
            tokio::time::sleep(d).await;
            // off the runtime's workers: `f` may take the node lock
            let _ = tokio::task::spawn_blocking(f).await;
        });
        true
    }

    /// Wakes the driver after `d` so waiters with a `late` time are looked at.
    pub fn timer(&self, d: Duration) {
        if let Net::Driver { ctl, handle, .. } = self {
            // a weak sender: a pending timer does not keep the driver alive
            let ctl = ctl.downgrade();
            handle.spawn(async move {
                tokio::time::sleep(d).await;
                if let Some(ctl) = ctl.upgrade() {
                    let _ = ctl.send(Control::Call(Box::new(|_| Vec::new())));
                }
            });
        }
    }
}

/// The driver task's future. A panic in it, or its runtime dropping it unfinished (the app shut
/// its runtime down with the node open), ends the node's sync: `driver_died`. The panic
/// then goes on to the runtime as before, so its message shows where task panics do.
struct Watched<F> {
    f: Pin<Box<F>>,
    db: WeakOsis,
    done: bool,
}

impl<F: Future> Future for Watched<F> {
    type Output = F::Output;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let me = &mut *self;
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| me.f.as_mut().poll(cx))) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(v)) => {
                me.done = true;
                Poll::Ready(v)
            }
            Err(p) => {
                me.done = true;
                let msg = p.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| p.downcast_ref::<String>().cloned()).unwrap_or_default();
                driver_died(&me.db, format!("sync driver panicked: {msg}"));
                std::panic::resume_unwind(p)
            }
        }
    }
}

impl<F> Drop for Watched<F> {
    fn drop(&mut self) {
        if !self.done {
            driver_died(&self.db, "sync stopped: its runtime shut down".into());
        }
    }
}

/// The driver is gone while the node may be open: every waiter fails with `why`, and so does
/// every later wait (`Net::died`, looked at under the same lock); reported as
/// `DiagnosticKind::SyncStopped`.
fn driver_died(db: &WeakOsis, why: String) {
    let Some(db) = db.hold() else { return };
    let Net::Driver { died, .. } = &db.inner.net else { return };
    {
        // the engine is not touched: it may be what panicked
        let mut g = lock(&db.inner.eng);
        *lock(died) = Some(why.clone());
        for w in g.waiters.drain(..) {
            w.slot.put(Err(Error::Network(why.clone())));
        }
    }
    // best effort, for the same reason (a second panic was already printed by the hook)
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        db.locked(|l| l.engine().report(osis_node::Diagnostic { kind: osis_node::DiagnosticKind::SyncStopped, tids: Vec::new(), commit: None, peer: None, detail: why.clone() }));
    }));
}

fn log_line(m: &str) {
    if std::env::var_os("OSIS_LOG").is_some() {
        eprintln!("osis sync: {m}");
    }
}

/// The driver's view of the handle: the sync engine behind the node lock, and where the
/// node lives (the host's store goes beside it).
struct OsisShared(WeakOsis, crate::Store);

impl Shared for OsisShared {
    fn with(&self, f: &mut dyn FnMut(&mut SyncEngine) -> Vec<Action>) -> Option<Vec<Action>> {
        let db = self.0.hold()?;
        db.handled(|l| f(&mut l.sync));
        Some(Vec::new())
    }

    fn host_store(&self) -> std::result::Result<osis_store::Store, String> {
        let (b, r): (Box<dyn osis_store::Backend>, Box<dyn osis_store::RootStorage>) = match &self.1 {
            crate::Store::Memory(m) => (Box::new(m.host.clone()), Box::new(m.host_root.clone())),
            crate::Store::Dir(p) => (Box::new(osis_store::RedbBackend::open(&p.join("host.redb")).map_err(|e| e.to_string())?), Box::new(osis_store::FileRoot::new(p.join("host.root")))),
        };
        osis_store::Store::open_or_create(b, r, osis_store::StoreConfig::default(), &mut osis_crypto::OsRng).map_err(|e| e.to_string())
    }

    fn erase_host_store(&self) -> std::result::Result<(), String> {
        use osis_store::RootStorage as _;
        match &self.1 {
            crate::Store::Memory(m) => {
                m.host_root.clone().erase().map_err(|e| e.to_string())?;
                m.host.erase();
            }
            crate::Store::Dir(p) => {
                osis_store::FileRoot::new(p.join("host.root")).erase().map_err(|e| e.to_string())?;
                match std::fs::remove_file(p.join("host.redb")) {
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.to_string()),
                    _ => {}
                }
            }
        }
        Ok(())
    }
}

/// Where a waiting call's result lands.
pub(crate) struct Slot<T> {
    /// The result until taken, who waits for it, whether one came.
    m: Mutex<(Option<T>, Option<Waker>, bool)>,
}

impl<T> Slot<T> {
    pub fn new() -> Arc<Slot<T>> {
        Arc::new(Slot { m: Mutex::new((None, None, false)) })
    }

    pub fn put(&self, v: T) {
        let mut g = lock(&self.m);
        g.0 = Some(v);
        g.2 = true;
        if let Some(w) = g.1.take() {
            w.wake();
        }
    }

    /// `put`, unless a result came first.
    fn put_unless_answered(&self, v: T) {
        if !lock(&self.m).2 {
            self.put(v);
        }
    }
}

/// A result another node's answer resolves (runtime-agnostic).
pub(crate) struct Pending<T> {
    slot: Arc<Slot<T>>,
}

impl<T> Pending<T> {
    /// A result known now.
    pub fn ready(v: T) -> Pending<T> {
        let slot = Slot::new();
        slot.put(v);
        Pending { slot }
    }

    /// A result its slot gets later.
    pub fn new() -> (Pending<T>, Arc<Slot<T>>) {
        let slot = Slot::new();
        (Pending { slot: slot.clone() }, slot)
    }
}

impl<T> Future for Pending<T> {
    type Output = T;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        let mut g = lock(&self.slot.m);
        match g.0.take() {
            Some(v) => Poll::Ready(v),
            None => {
                g.1 = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

/// The check gets whether its `late` time passed (`Osis::wait_until`).
pub(crate) type Check = Box<dyn FnMut(&mut SyncEngine, &Status, bool) -> Option<Result<()>> + Send>;

/// A condition on the sync state, looked at after every change.
pub(crate) struct Waiter {
    check: Check,
    late: Option<u64>,
    slot: Arc<Slot<Result<()>>>,
}

impl Waiter {
    /// Resolves the slot when the check answers; `true` when done.
    pub fn poll(&mut self, sync: &mut SyncEngine, status: &Status, now: u64) -> bool {
        // the future was dropped: nobody waits any more
        if Arc::strong_count(&self.slot) == 1 {
            return true;
        }
        let late = self.late.is_some_and(|d| now >= d);
        if let Some(r) = (self.check)(sync, status, late) {
            self.slot.put(r);
            return true;
        }
        false
    }
}

/// A node going away answers whoever still waits on it: a future holding no handle
/// (`Osis::wait_synced_pending`) would hear nothing else.
impl Drop for Waiter {
    fn drop(&mut self) {
        self.slot.put_unless_answered(Err(Error::Closed));
    }
}

impl crate::Osis {
    /// A future resolving once `check` answers. `late`: from this long on the check is told so
    /// (first at once for 0; past what a clock can name, never): it may then answer what it would
    /// not before. Fails at once with `Network` when nothing carries the network (`Runtime::None`).
    pub(crate) fn wait_until(&self, late: Option<Duration>, check: Check) -> Pending<Result<()>> {
        let slot = Slot::new();
        if !self.inner.net.online() {
            slot.put(Err(Error::Network("no runtime: sync is off (Config.runtime)".into())));
            return Pending { slot };
        }
        let now = self.inner.clock.now_wall_ms().0;
        let at = late.and_then(|d| u64::try_from(d.as_millis()).ok()).and_then(|d| now.checked_add(d));
        let mut w = Waiter { check, late: at, slot: slot.clone() };
        let waiting = self.locked(|l| {
            if w.poll(&mut l.sync, &l.status, now) {
                return false;
            }
            // the driver died: nothing would answer
            if let Some(e) = self.inner.net.died() {
                w.slot.put(Err(e));
                return false;
            }
            l.waiters.push(w);
            true
        });
        if let (true, Some(_), Some(d)) = (waiting, at, late) {
            self.inner.net.timer(d);
        }
        Pending { slot }
    }
}

/// Whether a group's readers are told how to reach this node directly, so that they can sync with
/// it off the LAN too.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ShareAddress {
    /// Only when every reader of the group is this account, a thing it owns or a contact.
    #[default]
    Auto,
    /// Tell its readers, whoever they are.
    Always,
    /// Tell no one, so its readers do not dial this node.
    Never,
}

/// How much of a group this node holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SyncMode {
    /// All of it.
    #[default]
    Full,
    /// None of its content: nothing of it is downloaded or uploaded from here, and what is already
    /// here stays, no longer updated. Lowering a role reads only the log of who changed what, so
    /// that the holder's edits there are kept.
    LogOnly,
}

/// How this node syncs a group (`Osis::sync_options`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SyncOptions {
    /// Who is told this node's address.
    pub share_address: ShareAddress,
    /// How much of the group this node holds.
    pub mode: SyncMode,
}

impl crate::Osis {
    /// How this node syncs `group` (the default when never set).
    /// `Unsupported` on a client with its own actor.
    pub fn sync_options(&self, group: osis_base::Tid) -> crate::Result<SyncOptions> {
        if !self.has_store() {
            let v = self.rcall(crate::port::method::SYNC_OPTIONS, vec![Value::Tid(group)])?;
            let mut a = crate::port::codec::Args::new(v)?;
            return crate::port::codec::sync_options(&mut a);
        }
        Ok(self.locked(|x| SyncOptions {
            share_address: match x.sync.reach_policy(&group) {
                None => ShareAddress::Auto,
                Some(true) => ShareAddress::Always,
                Some(false) => ShareAddress::Never,
            },
            mode: if x.sync.receipts_only().contains(&group) { SyncMode::LogOnly } else { SyncMode::Full },
        }))
    }

    /// Sets how this node syncs `group` (stored): all of it, so to change one field start from
    /// `sync_options`. Readers of a group not told this node's address do not dial it. When a group
    /// was told it and no longer qualifies, the address changes (`rotate_peer_address`), so readers there
    /// cannot dial it any more.
    /// `Unsupported` on a client with its own actor.
    pub fn set_sync_options(&self, group: osis_base::Tid, o: SyncOptions) -> crate::Result<()> {
        if !self.has_store() {
            let mut args = vec![Value::Tid(group)];
            args.extend(crate::port::codec::sync_options_v(&o));
            return self.rcall(crate::port::method::SET_SYNC_OPTIONS, args).map(drop);
        }
        let reach = match o.share_address {
            ShareAddress::Auto => None,
            ShareAddress::Always => Some(true),
            ShareAddress::Never => Some(false),
        };
        let headers = o.mode == SyncMode::LogOnly;
        self.act(|l| {
            let mut acts = l.sync.set_reach_policy(group, reach);
            if l.sync.receipts_only().contains(&group) != headers {
                acts.extend(l.sync.set_receipts_only(group, headers));
            }
            acts
        });
        Ok(())
    }

    /// Serves clients on this store's own unix socket: by default, processes of this uid that
    /// connect (`Osis::connect_socket` with this store's directory) act as this node's main actor
    /// with no authentication (there is no security boundary between them); others are refused by
    /// the kernel's word for their uid. A stale socket is replaced, one in use is `Network`; `Storage`
    /// when the socket's directory is not safely this user's or too long a path; `Invalid` for a store in memory, which
    /// has no directory to name it by. Needs a runtime.
    /// `Unsupported` on a thin client.
    pub fn listen_socket(&self) -> crate::Result<()> {
        self.local_only("listen_socket")?;
        let Some(dir) = &self.inner.store_dir else { return Err(crate::Error::Invalid("a store in memory has no client socket".into())) };
        self.listen_socket_at(&crate::port::client::socket_path(dir)?)
    }

    pub(crate) fn listen_socket_at(&self, path: &std::path::Path) -> crate::Result<()> {
        self.local_only("listen_socket")?;
        let url = osis_transport::unix::url_of(path);
        osis_transport::unix::url_path(&url).map_err(|e| crate::Error::Invalid(e.to_string()))?;
        self.inner.net.listen(url)
    }

    /// Serves clients at `urls` (`quic://example.org:4040`), by default only as actors they authenticate for
    /// (`add_client`), with a key of
    /// the client listener's own, made on first use and kept in the store: `rotate_peer_address` leaves it
    /// be, and nothing ties it to this node's other keys. Returns each
    /// address to hand clients (with its real port). Replaces the listeners of an earlier call
    /// (their sessions end; clients reconnect by themselves). No URL: stops listening, ends those sessions, shreds the key (a later
    /// call makes a new one, so clients need a new address). All or none: on an error nothing
    /// listens. Needs a runtime. Listening does not last past this process: call it at each start.
    /// `Unsupported` on a thin client.
    pub fn client_listen(&self, urls: &[crate::Url]) -> crate::Result<Vec<crate::Address>> {
        self.local_only("client_listen")?;
        let a = self.inner.net.client_listen(driver::ClientUrls::Listen(urls.iter().map(ToString::to_string).collect()))?;
        Ok(a.into_iter().map(|a| crate::Address(osis_label::Address { url: a.url, key: a.key })).collect())
    }

    /// New client addresses (by hand only): the old key is shredded,
    /// its listeners and sessions end, and the same addresses listen under the new one, returned
    /// here. A client holding the old address sees `Network` on every call and `connected: false`
    /// until it connects to a new address, handed to it out of band. No listener up (a process
    /// that has not called `client_listen`): only the key changes. Needs a runtime.
    /// `Unsupported` on a client with its own actor.
    pub fn rotate_client_address(&self) -> crate::Result<Vec<crate::Address>> {
        if !self.has_store() {
            let v = self.rcall(crate::port::method::ROTATE_CLIENT_ADDRESS, vec![])?;
            return crate::port::codec::Args::of(vec![v]).list()?.into_iter().map(|h| crate::port::codec::Args::of(vec![h]).text()?.parse()).collect();
        }
        let a = self.inner.net.client_listen(driver::ClientUrls::Rotate)?;
        Ok(a.into_iter().map(|a| crate::Address(osis_label::Address { url: a.url, key: a.key })).collect())
    }

    /// Gives this node a new address other nodes dial it directly at (`Config::direct_sync`): it listens
    /// there at once and tells only the groups whose `ShareAddress` allows it. A node removed from
    /// those since can no longer dial it or recognise it on a LAN, nor can a holder of a direct link.
    /// Direct links still open no longer reach this node directly (they still work through saved peers).
    /// Done by itself when a group told the old address no longer qualifies and when a direct link
    /// ends.
    /// `Unsupported` on a client with its own actor.
    pub fn rotate_peer_address(&self) -> crate::Result<()> {
        if !self.has_store() {
            return self.rcall(crate::port::method::ROTATE_PEER_ADDRESS, vec![]).map(drop);
        }
        self.act(|l| l.sync.rotate_reach());
        Ok(())
    }
}
