//! Background sync (notes/api.md Design rules): the sync engine's network actions leave through
//! `Net`, a tokio driver (osis-node `sync::driver::run_host`) over the handle's lock, or a queue
//! a test harness carries (`Runtime::Manual`). Futures of the calls that wait for another node
//! are runtime-agnostic: a `Waiter` checked after every change under the lock resolves a
//! `Pending` through a slot.

use crate::error::{Error, Result};
use crate::handle::WeakOsis;
use crate::share::Status;
use crate::watch::lock;
use osis_base::Clock;
use osis_node::sync::driver::{self, Control, Host};
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
    /// The app's tokio runtime (multi-thread recommended: engine calls block in place).
    Tokio(tokio::runtime::Handle),
    /// A small tokio runtime of osis's own.
    Own,
    /// A test harness carries the actions (`Osis::take_actions`, `Osis::feed`) of every
    /// database opened with this registry.
    #[doc(hidden)]
    Manual(ManualNet),
}

/// The databases a test harness drives (`Runtime::Manual`), in the order they started.
#[doc(hidden)]
#[derive(Clone, Debug, Default)]
pub struct ManualNet(Arc<Mutex<Vec<WeakOsis>>>);

impl ManualNet {
    pub fn new() -> ManualNet {
        ManualNet::default()
    }

    /// The databases still open, by start order (`None`: closed).
    pub fn dbs(&self) -> Vec<Option<crate::Osis>> {
        lock(&self.0).iter().map(|w| w.upgrade()).collect()
    }

    pub(crate) fn register(&self, db: WeakOsis) {
        lock(&self.0).push(db);
    }
}

/// How servers and co-reader nodes are dialed (spec/sync.md §10).
#[derive(Clone)]
pub enum Transport {
    /// Servers over QUIC (feature `quic`); co-readers over iroh (feature `iroh`, through
    /// `Config.relays`), on the LAN too with feature `lan`. Without `iroh` no co-reader is dialed.
    #[cfg(feature = "quic")]
    Quic,
    /// In-process endpoints for servers and co-readers (tests).
    InProcess(osis_transport::InProcess),
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "quic")]
            Transport::Quic => f.write_str("Quic"),
            Transport::InProcess(_) => f.write_str("InProcess"),
        }
    }
}

pub(crate) enum Net {
    Off,
    Manual(Mutex<Vec<Action>>),
    Driver { ctl: mpsc::UnboundedSender<Control>, handle: tokio::runtime::Handle, own: Mutex<Option<tokio::runtime::Runtime>> },
}

impl Drop for Net {
    fn drop(&mut self) {
        if let Net::Driver { ctl, .. } = self {
            // the driver ends now, not when its last timer fires
            let _ = ctl.send(Control::Shutdown);
        }
        if let Net::Driver { own, .. } = self
            && let Some(rt) = lock(own).take()
        {
            // may run on one of its own workers: never block here
            rt.shutdown_background();
        }
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
        let (ctl, rx) = mpsc::unbounded_channel();
        Ok((Net::Driver { ctl, handle, own: Mutex::new(own) }, Some(rx)))
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

    /// Starts the driver task over one transport for servers and co-readers (`Multi`). With
    /// `p2p` (`Config.peers`) and a co-reader transport, it listens with the dialable secret
    /// (registered at `relays`) and publishes `/reach`; with feature `lan` and QUIC it also runs
    /// the LAN loop. Without a co-reader transport no co-reader is dialed.
    pub fn spawn_driver(&self, rx: mpsc::UnboundedReceiver<Control>, transport: Option<Transport>, p2p: bool, relays: Vec<String>, clock: Arc<dyn Clock>, db: WeakOsis) -> Result<()> {
        let Net::Driver { handle, ctl, .. } = self else { return Ok(()) };
        let host = OsisHost(db);
        let log: driver::Log = Arc::new(|m: &str| log_line(m));
        let mut multi = osis_transport::Multi::default();
        // where the dialable-key listener goes, and whether the LAN loop runs
        let (reach, lan): (Option<String>, bool) = match transport {
            Some(Transport::InProcess(t)) => {
                let url = format!("mem://{}-peer", t.name());
                multi.mem = Some(t);
                (Some(url), false)
            }
            #[cfg(feature = "quic")]
            Some(Transport::Quic) | None => {
                multi.quic = Some(osis_transport::Quic::new());
                #[cfg(feature = "iroh")]
                {
                    multi.iroh = Some(osis_transport::Iroh::new());
                    (Some(osis_transport::peer_url(&relays)), cfg!(feature = "lan"))
                }
                #[cfg(not(feature = "iroh"))]
                (None, false)
            }
            #[cfg(not(feature = "quic"))]
            None => return Err(Error::Invalid("a runtime needs a transport (Config.transport; QUIC needs feature `quic`)".into())),
        };
        handle.spawn(driver::run_host(host, multi, Vec::new(), clock, rx, log));
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

    /// Runs `f` on the runtime after `d`; `false` (and `f` dropped) without one.
    pub fn after(&self, d: Duration, f: Box<dyn FnOnce() + Send>) -> bool {
        let Net::Driver { handle, .. } = self else { return false };
        handle.spawn(async move {
            tokio::time::sleep(d).await;
            // off the runtime's workers: `f` may take the database lock
            let _ = tokio::task::spawn_blocking(f).await;
        });
        true
    }

    /// Wakes the driver after `d` so waiters with a deadline are looked at.
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

fn log_line(m: &str) {
    if std::env::var_os("OSIS_LOG").is_some() {
        eprintln!("osis sync: {m}");
    }
}

/// The driver's view of the handle: the sync engine behind the database lock.
struct OsisHost(WeakOsis);

impl Host for OsisHost {
    fn with(&self, f: &mut dyn FnMut(&mut SyncEngine) -> Vec<Action>) -> Option<Vec<Action>> {
        let db = self.0.upgrade()?;
        db.handled(|l| f(&mut l.sync));
        Some(Vec::new())
    }
}

/// Where a waiting call's result lands.
pub(crate) struct Slot<T> {
    m: Mutex<(Option<T>, Option<Waker>)>,
}

impl<T> Slot<T> {
    pub fn new() -> Arc<Slot<T>> {
        Arc::new(Slot { m: Mutex::new((None, None)) })
    }

    pub fn put(&self, v: T) {
        let mut g = lock(&self.m);
        g.0 = Some(v);
        if let Some(w) = g.1.take() {
            w.wake();
        }
    }
}

/// A result another node's answer resolves (runtime-agnostic).
pub(crate) struct Pending<T> {
    slot: Arc<Slot<T>>,
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

pub(crate) type Check = Box<dyn FnMut(&mut SyncEngine, &Status) -> Option<Result<()>> + Send>;

/// A condition on the sync state, looked at after every change.
pub(crate) struct Waiter {
    check: Check,
    deadline: Option<u64>,
    slot: Arc<Slot<Result<()>>>,
}

impl Waiter {
    /// Resolves the slot when the check answers or the deadline passed; `true` when done.
    pub fn poll(&mut self, sync: &mut SyncEngine, status: &Status, now: u64) -> bool {
        // the future was dropped: nobody waits any more
        if Arc::strong_count(&self.slot) == 1 {
            return true;
        }
        if let Some(r) = (self.check)(sync, status) {
            self.slot.put(r);
            return true;
        }
        if self.deadline.is_some_and(|d| now >= d) {
            self.slot.put(Err(Error::Network("timed out".into())));
            return true;
        }
        false
    }
}

impl crate::Osis {
    /// A future resolving once `check` answers (or `Network` after `timeout`). Fails at once
    /// with `Network` when nothing carries the network (`Runtime::None`).
    pub(crate) fn wait_until(&self, timeout: Option<Duration>, check: Check) -> Pending<Result<()>> {
        let slot = Slot::new();
        if !self.inner.net.online() {
            slot.put(Err(Error::Network("no runtime: sync is off (Config.runtime)".into())));
            return Pending { slot };
        }
        let now = self.inner.clock.now_wall_ms().0;
        let deadline = timeout.map(|d| now.saturating_add(u64::try_from(d.as_millis()).unwrap_or(u64::MAX)));
        let mut w = Waiter { check, deadline, slot: slot.clone() };
        self.locked(|l| {
            if !w.poll(&mut l.sync, &l.status, now) {
                l.waiters.push(w);
            }
        });
        if let Some(d) = timeout {
            self.inner.net.timer(d);
        }
        Pending { slot }
    }
}

/// A group's sync policy (`Osis::sync_policy`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GroupPolicy {
    /// Whether this node's `/reach` (its dialable key) goes under the group's labels, so
    /// co-readers there can dial it off the LAN (spec/permissions.md §4). `None`: only when
    /// every reader of the group is this person, a thing it owns or a contact (`import_contact`).
    pub publish_reach: Option<bool>,
}

impl crate::Osis {
    /// Sets `group`'s sync policy (stored). Co-readers of groups without `/reach` are not
    /// dialed. When the group's labels already hold this node's `/reach` and it no longer goes
    /// there, the node's reach rotates (`rotate_reach`), so readers there cannot dial it any more.
    pub fn sync_policy(&self, group: osis_base::Tid, policy: GroupPolicy) {
        self.locked(|l| {
            let acts = l.sync.set_reach_policy(group, policy.publish_reach);
            self.inner.net.apply(acts);
        });
    }

    /// Gives this device a new dialable key and LAN secret (spec/sync.md §10): it listens with
    /// the new key at once and publishes it only under groups that get `/reach`. A co-reader
    /// removed since can no longer dial it or recognise it on a LAN; a link holder (who got the
    /// dialable key from a direct link, never the lan secret) can no longer dial it. Direct links
    /// still open lose first contact (they still work through servers). Done by itself when a
    /// group holding its `/reach` stops qualifying and when a direct link ends.
    pub fn rotate_reach(&self) {
        self.locked(|l| {
            let acts = l.sync.rotate_reach();
            self.inner.net.apply(acts);
        });
    }
}
