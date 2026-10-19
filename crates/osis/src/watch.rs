//! Watching (notes/api.md Watching): one dispatcher thread per database runs every callback, in
//! commit order, after the commit is durable, never under a lock. Engine events are drained into
//! the dispatcher's queue under the engine lock, each with a sequence number; a subscription
//! ignores messages queued before it registered, so a watch taken atomically with the current
//! value misses nothing and sees nothing twice. Callbacks read the latest state when they run
//! (coalescing) and skip a value equal to the one they last delivered.

use crate::error::{Error, Result};
use crate::handle::{Inner, Osis};
use osis_core::{Ak, CommitId, Tid, Ts, Value, WallMs};
use osis_node::{Cause, Diagnostic, Event, Origin};
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, Weak};
use std::task::{Context, Poll, Waker};
use std::thread::ThreadId;
use std::time::{Duration, Instant};

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// The commit behind a change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitInfo {
    pub id: CommitId,
    /// The actor the author acted for.
    pub actor: Tid,
    /// The authoring node.
    pub node: Tid,
    pub ts: Ts,
    /// When this node received it. Display time for feeds is `min(ts, received)`.
    pub received: WallMs,
}

/// Why a watched value changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The first call of `on_change`, with the value at registration.
    Initial,
    /// A commit made on this node.
    Local(CommitInfo),
    /// A commit received from another node.
    Remote(CommitInfo),
    /// No commit: validity, expiry, purge or a late part of a commit changed the read.
    Derived(Cause),
}

/// One change of an aspect.
#[derive(Clone, Debug, PartialEq)]
pub struct Change<T> {
    pub tid: Tid,
    pub ak: Ak,
    /// The value now (`None`: absent), or why it cannot be read (`TooLarge`, `Type`).
    pub value: Result<Option<T>>,
    pub source: Source,
}

/// What a subscription listens to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Filter {
    Aspect(Tid, Ak),
    Thing(Tid),
    Roster(Tid),
    Diagnostics,
    Signal(Tid, String),
}

/// A locally delivered signal.
#[derive(Clone, Debug)]
pub(crate) struct SignalMsg {
    pub tid: Tid,
    pub kind: String,
    pub value: Value,
    pub actor: Tid,
    pub node: Tid,
    pub ts: WallMs,
}

/// What a callback is called with.
#[derive(Clone, Debug)]
pub(crate) enum Delivery {
    Initial,
    Aspect { ak: Ak, source: Source },
    Roster,
    Diagnostic(Diagnostic),
    Signal(SignalMsg),
}

pub(crate) enum Msg {
    Event(Event),
    Initial(u64),
    Signal(SignalMsg),
    Barrier(Sender<()>),
}

pub(crate) type Callback = Box<dyn FnMut(&Osis, Delivery) + Send>;

pub(crate) struct Sub {
    since: u64,
    filter: Filter,
    removed: AtomicBool,
    cb: Mutex<Callback>,
}

#[derive(Default)]
pub(crate) struct Registry {
    next: u64,
    subs: BTreeMap<u64, Arc<Sub>>,
}

/// The dispatcher's sending side, kept by the database.
pub(crate) struct Dispatch {
    tx: Sender<(u64, Msg)>,
    pub registry: Arc<Mutex<Registry>>,
    thread: OnceLock<ThreadId>,
}

pub(crate) type Queue = Receiver<(u64, Msg)>;

impl Dispatch {
    pub fn new() -> (Dispatch, Queue) {
        let (tx, rx) = channel();
        (Dispatch { tx, registry: Arc::default(), thread: OnceLock::new() }, rx)
    }

    /// Starts the dispatcher thread; it runs until the database closes.
    pub fn spawn(&self, rx: Queue, db: Weak<Inner>) -> Result<()> {
        let reg = self.registry.clone();
        let h = std::thread::Builder::new().name("osis-dispatch".into()).spawn(move || run(rx, reg, db)).map_err(|e| Error::Storage(e.to_string()))?;
        let _ = self.thread.set(h.thread().id());
        Ok(())
    }

    /// Queues a message with sequence number `seq` (taken under the engine lock).
    pub fn send(&self, seq: u64, m: Msg) {
        let _ = self.tx.send((seq, m));
    }

    /// Registers a callback for messages from sequence `since` on.
    pub fn register(&self, since: u64, filter: Filter, cb: Callback) -> Subscription {
        let mut r = lock(&self.registry);
        r.next += 1;
        let id = r.next;
        r.subs.insert(id, Arc::new(Sub { since, filter, removed: AtomicBool::new(false), cb: Mutex::new(cb) }));
        Subscription { registry: Arc::downgrade(&self.registry), id: Some(id) }
    }

    pub fn on_dispatcher(&self) -> bool {
        self.thread.get() == Some(&std::thread::current().id())
    }

    /// Blocks until every message queued so far has been dispatched.
    pub fn settle(&self) {
        if self.on_dispatcher() {
            return;
        }
        let (tx, rx) = channel();
        if self.tx.send((0, Msg::Barrier(tx))).is_ok() {
            let _ = rx.recv();
        }
    }
}

fn info(id: CommitId, author: Tid, actor: Tid, ts: Ts, received: WallMs) -> CommitInfo {
    CommitInfo { id, actor, node: author, ts, received }
}

/// Which subscriptions a message reaches, with what.
fn targets(r: &Registry, seq: u64, m: &Msg) -> Vec<(Arc<Sub>, Delivery)> {
    let live = r.subs.values().filter(|s| s.since <= seq);
    let aspects = |changed: &[(Tid, Ak)], source: Source| -> Vec<(Arc<Sub>, Delivery)> {
        let mut out = Vec::new();
        for s in r.subs.values().filter(|s| s.since <= seq) {
            for (t, ak) in changed {
                let hit = match &s.filter {
                    Filter::Aspect(ft, fak) => ft == t && fak == ak,
                    Filter::Thing(ft) => ft == t,
                    _ => false,
                };
                if hit {
                    out.push((s.clone(), Delivery::Aspect { ak: ak.clone(), source }));
                }
            }
        }
        out
    };
    match m {
        Msg::Event(Event::Applied { id, origin, author, actor, ts, received, changed }) => {
            let i = info(*id, *author, *actor, *ts, *received);
            aspects(changed, if *origin == Origin::Local { Source::Local(i) } else { Source::Remote(i) })
        }
        Msg::Event(Event::Changed { cause, changed }) => aspects(changed, Source::Derived(*cause)),
        Msg::Event(Event::Roster { thing }) => live.filter(|s| s.filter == Filter::Roster(*thing)).map(|s| (s.clone(), Delivery::Roster)).collect(),
        Msg::Event(Event::Diagnostic(d)) => live.filter(|s| s.filter == Filter::Diagnostics).map(|s| (s.clone(), Delivery::Diagnostic(d.clone()))).collect(),
        // remote signals and sync status arrive with node-sync (plans/api.md second half)
        Msg::Event(_) => Vec::new(),
        Msg::Initial(id) => r.subs.get(id).map(|s| (s.clone(), Delivery::Initial)).into_iter().collect(),
        Msg::Signal(sig) => live.filter(|s| s.filter == Filter::Signal(sig.tid, sig.kind.clone())).map(|s| (s.clone(), Delivery::Signal(sig.clone()))).collect(),
        Msg::Barrier(_) => Vec::new(),
    }
}

fn run(rx: Receiver<(u64, Msg)>, registry: Arc<Mutex<Registry>>, db: Weak<Inner>) {
    while let Ok((seq, m)) = rx.recv() {
        if let Msg::Barrier(done) = m {
            let _ = done.send(());
            continue;
        }
        let Some(inner) = db.upgrade() else { continue };
        let db = Osis::from_inner(inner);
        let ts = targets(&lock(&registry), seq, &m);
        for (s, d) in ts {
            if s.removed.load(Ordering::Acquire) {
                continue;
            }
            let mut cb = lock(&s.cb);
            cb(&db, d);
        }
    }
}

/// A registration; dropping it unsubscribes (notes/api.md: RAII, no ids to remember).
#[must_use = "dropping a Subscription unsubscribes at once; use detach() to keep it"]
pub struct Subscription {
    registry: Weak<Mutex<Registry>>,
    id: Option<u64>,
}

impl Subscription {
    /// Keeps the subscription for the database's life.
    pub fn detach(mut self) {
        self.id = None;
    }

    pub(crate) fn id(&self) -> Option<u64> {
        self.id
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        let (Some(id), Some(r)) = (self.id, self.registry.upgrade()) else { return };
        if let Some(s) = lock(&r).subs.remove(&id) {
            s.removed.store(true, Ordering::Release);
        }
    }
}

impl std::fmt::Debug for Subscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Subscription({:?})", self.id)
    }
}

pub(crate) struct WatchState {
    m: Mutex<WState>,
    cv: Condvar,
}

struct WState {
    value: Result<Option<Value>>,
    version: u64,
    wakers: Vec<Waker>,
}

impl WatchState {
    pub fn new(value: Result<Option<Value>>) -> Arc<WatchState> {
        Arc::new(WatchState { m: Mutex::new(WState { value, version: 0, wakers: Vec::new() }), cv: Condvar::new() })
    }

    /// Stores a new value if it differs from the held one.
    pub fn update(&self, v: Result<Option<Value>>) {
        let mut s = lock(&self.m);
        if s.value == v {
            return;
        }
        s.value = v;
        s.version += 1;
        for w in s.wakers.drain(..) {
            w.wake();
        }
        self.cv.notify_all();
    }
}

type Decode<T> = Arc<dyn Fn(&Value) -> Result<T> + Send + Sync>;

/// A watched aspect: the latest value, taken atomically with the subscription (notes/api.md
/// Watching). Holds only the latest value; unsubscribes when dropped.
pub struct Watch<T> {
    state: Arc<WatchState>,
    seen: AtomicU64,
    decode: Decode<T>,
    _sub: Subscription,
}

impl<T> Watch<T> {
    pub(crate) fn new(state: Arc<WatchState>, decode: Decode<T>, sub: Subscription) -> Watch<T> {
        Watch { state, seen: AtomicU64::new(0), decode, _sub: sub }
    }

    /// The latest value (`None`: absent).
    pub fn current(&self) -> Result<Option<T>> {
        let s = lock(&self.state.m);
        match &s.value {
            Ok(Some(v)) => (self.decode)(v).map(Some),
            Ok(None) => Ok(None),
            Err(e) => Err(e.clone()),
        }
    }

    /// Whether the value changed since the last `changed*` call returned (non-blocking; marks
    /// it seen).
    pub fn try_changed(&self) -> bool {
        let v = lock(&self.state.m).version;
        self.seen.swap(v, Ordering::AcqRel) < v
    }

    /// Blocks until the value changes or `d` passes; `true` if it changed.
    pub fn changed_timeout(&self, d: Duration) -> bool {
        let end = Instant::now() + d;
        let mut s = lock(&self.state.m);
        loop {
            if s.version > self.seen.load(Ordering::Acquire) {
                self.seen.store(s.version, Ordering::Release);
                return true;
            }
            let now = Instant::now();
            if now >= end {
                return false;
            }
            s = self.state.cv.wait_timeout(s, end - now).map(|(g, _)| g).unwrap_or_else(|p| p.into_inner().0);
        }
    }

    /// Resolves when the value changes (runtime-agnostic).
    pub fn changed(&self) -> Changed<'_, T> {
        Changed { w: self }
    }
}

/// Future of `Watch::changed`.
pub struct Changed<'a, T> {
    w: &'a Watch<T>,
}

impl<T> Future for Changed<'_, T> {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut s = lock(&self.w.state.m);
        if s.version > self.w.seen.load(Ordering::Acquire) {
            self.w.seen.store(s.version, Ordering::Release);
            return Poll::Ready(());
        }
        s.wakers.push(cx.waker().clone());
        Poll::Pending
    }
}

impl<T> std::fmt::Debug for Watch<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Watch")
    }
}
