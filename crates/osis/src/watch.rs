//! Watching (notes/api.md Watching): one dispatcher thread per database runs every callback, in
//! commit order, after the commit is durable, never under a lock. Engine events are drained into
//! the dispatcher's queue under the engine lock, each with a sequence number; a subscription
//! ignores messages queued before it registered, so a watch taken atomically with the current
//! value misses nothing and sees nothing twice. A call reads the aspect's latest state
//! (coalescing: later queued events for that aspect are folded in, and the call carries the
//! source of the newest of them); a value equal to the last one delivered is skipped, an error
//! never is. A panicking callback becomes a diagnostic; the dispatcher lives on.

use crate::error::{Error, Result};
use crate::handle::{Inner, Osis};
use osis_core::{Ak, CommitId, Tid, Ts, Value, WallMs};
use osis_node::{Cause, Diagnostic, DiagnosticKind, Event, Origin};
use std::collections::{BTreeMap, HashMap, VecDeque};
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
    Status,
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
    /// `value` is the aspect read when the call was prepared; `source` the last event whose
    /// effect it shows.
    Aspect { tid: Tid, ak: Ak, source: Source, value: Result<Option<Value>> },
    Roster,
    Diagnostic(Diagnostic),
    Signal(SignalMsg),
    Status(crate::share::Status),
}

pub(crate) enum Msg {
    Event(Event),
    Initial(u64),
    Status(crate::share::Status),
    Barrier(Sender<()>),
}

pub(crate) type Callback = Box<dyn FnMut(&Osis, Delivery) + Send>;

pub(crate) struct Sub {
    id: u64,
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

/// State shared by the database, the dispatcher and subscriptions.
#[derive(Default)]
pub(crate) struct Shared {
    registry: Mutex<Registry>,
    /// The thread holding the engine lock, if any (a subscription dropped there must not wait
    /// for an in-flight call: that call may be waiting for the engine lock).
    pub holder: Mutex<Option<ThreadId>>,
    thread: OnceLock<ThreadId>,
}

impl Shared {
    fn on_dispatcher(&self) -> bool {
        self.thread.get() == Some(&std::thread::current().id())
    }
}

/// The dispatcher's sending side, kept by the database.
pub(crate) struct Dispatch {
    tx: Sender<(u64, Msg)>,
    pub shared: Arc<Shared>,
}

pub(crate) type Queue = Receiver<(u64, Msg)>;

impl Dispatch {
    pub fn new() -> (Dispatch, Queue) {
        let (tx, rx) = channel();
        (Dispatch { tx, shared: Arc::default() }, rx)
    }

    /// Starts the dispatcher thread; it runs until the database closes.
    pub fn spawn(&self, rx: Queue, db: Weak<Inner>) -> Result<()> {
        let sh = self.shared.clone();
        let h = std::thread::Builder::new().name("osis-dispatch".into()).spawn(move || run(rx, sh, db)).map_err(|e| Error::Storage(e.to_string()))?;
        let _ = self.shared.thread.set(h.thread().id());
        Ok(())
    }

    /// Queues a message with sequence number `seq` (taken under the engine lock).
    pub fn send(&self, seq: u64, m: Msg) {
        let _ = self.tx.send((seq, m));
    }

    /// Registers a callback for messages from sequence `since` on.
    pub fn register(&self, since: u64, filter: Filter, cb: Callback) -> Subscription {
        let mut r = lock(&self.shared.registry);
        r.next += 1;
        let id = r.next;
        r.subs.insert(id, Arc::new(Sub { id, since, filter, removed: AtomicBool::new(false), cb: Mutex::new(cb) }));
        Subscription { shared: Arc::downgrade(&self.shared), id: Some(id) }
    }

    /// Blocks until every message queued so far has been dispatched.
    pub fn settle(&self) {
        if self.shared.on_dispatcher() {
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

/// The aspects an event changed, with its source.
fn aspect_event(m: &Msg) -> Option<(&[(Tid, Ak)], Source)> {
    match m {
        Msg::Event(Event::Applied { id, origin, author, actor, ts, received, changed }) => {
            let i = info(*id, *author, *actor, *ts, *received);
            Some((changed, if *origin == Origin::Local { Source::Local(i) } else { Source::Remote(i) }))
        }
        Msg::Event(Event::Changed { cause, changed }) => Some((changed, Source::Derived(*cause))),
        _ => None,
    }
}

/// A call before its value is read.
enum Pre {
    Aspect { tid: Tid, ak: Ak, source: Source },
    Ready(Delivery),
}

/// Which subscriptions a message reaches. Aspect and thing watches follow moves: a watch
/// registered under `t` fires for changes of the thing `t` resolves to (spec/permissions.md §7).
fn targets(db: &Osis, sh: &Shared, seq: u64, m: &Msg) -> Vec<(Arc<Sub>, Pre)> {
    if let Msg::Initial(id) = m {
        return lock(&sh.registry).subs.get(id).map(|s| (s.clone(), Pre::Ready(Delivery::Initial))).into_iter().collect();
    }
    let live: Vec<Arc<Sub>> = lock(&sh.registry).subs.values().filter(|s| s.since <= seq).cloned().collect();
    let to = |f: &dyn Fn(&Filter) -> bool, d: Delivery| live.iter().filter(|s| f(&s.filter)).map(|s| (s.clone(), Pre::Ready(d.clone()))).collect();
    if let Some((changed, source)) = aspect_event(m) {
        let mut resolved: BTreeMap<Tid, Tid> = BTreeMap::new();
        let mut out = Vec::new();
        for s in &live {
            let ft = match &s.filter {
                Filter::Aspect(t, _) | Filter::Thing(t) => *t,
                _ => continue,
            };
            let rt = *resolved.entry(ft).or_insert_with(|| db.read(|r| r.resolve(ft)));
            for (t, ak) in changed {
                let hit = (ft == *t || rt == *t)
                    && match &s.filter {
                        Filter::Aspect(_, fak) => fak == ak,
                        _ => true,
                    };
                if hit {
                    out.push((s.clone(), Pre::Aspect { tid: *t, ak: ak.clone(), source }));
                }
            }
        }
        return out;
    }
    match m {
        Msg::Event(Event::Roster { thing }) => to(&|f| *f == Filter::Roster(*thing), Delivery::Roster),
        Msg::Event(Event::Diagnostic(d)) => to(&|f| *f == Filter::Diagnostics, Delivery::Diagnostic(d.clone())),
        Msg::Event(Event::Signal { tid, kind, from, actor, ts, target, value }) => {
            if target.is_some_and(|t| t != db.node()) {
                return Vec::new();
            }
            let sig = SignalMsg { tid: *tid, kind: kind.as_str().to_string(), value: value.clone(), actor: *actor, node: *from, ts: ts.wall_ms() };
            to(&|f| *f == Filter::Signal(sig.tid, sig.kind.clone()), Delivery::Signal(sig.clone()))
        }
        Msg::Status(st) => to(&|f| *f == Filter::Status, Delivery::Status(st.clone())),
        _ => Vec::new(),
    }
}

fn run(rx: Queue, sh: Arc<Shared>, db: Weak<Inner>) {
    let mut buf: VecDeque<(u64, Msg)> = VecDeque::new();
    // (subscription, tid, ak) -> last sequence number a coalesced call already showed
    let mut covered: HashMap<(u64, Tid, Ak), u64> = HashMap::new();
    loop {
        let (seq, m) = match buf.pop_front() {
            Some(x) => x,
            None => match rx.recv() {
                Ok(x) => x,
                Err(_) => return,
            },
        };
        if let Msg::Barrier(done) = m {
            let _ = done.send(());
            continue;
        }
        let Some(inner) = db.upgrade() else { continue };
        let db = Osis::from_inner(inner);
        covered.retain(|_, c| *c >= seq);
        for (s, pre) in targets(&db, &sh, seq, &m) {
            let d = match pre {
                Pre::Ready(d) => d,
                Pre::Aspect { tid, ak, mut source } => {
                    let key = (s.id, tid, ak.clone());
                    if covered.contains_key(&key) {
                        continue;
                    }
                    // read under the engine lock, queueing every event whose effect it shows;
                    // the call carries the source of the newest such event for this aspect
                    let value = db.value_with(tid, &ak, || buf.extend(rx.try_iter()));
                    let mut last = seq;
                    for (s2, m2) in &buf {
                        if let Some((changed, src)) = aspect_event(m2)
                            && changed.iter().any(|(t, a)| *t == tid && *a == ak)
                        {
                            source = src;
                            last = *s2;
                        }
                    }
                    if last > seq {
                        covered.insert(key, last);
                    }
                    Delivery::Aspect { tid, ak, source, value }
                }
            };
            call(&db, &s, d);
        }
    }
}

/// Runs one callback; a panic is caught, reported as a diagnostic, and the dispatcher lives on.
fn call(db: &Osis, s: &Sub, d: Delivery) {
    if s.removed.load(Ordering::Acquire) {
        return;
    }
    let mut cb = lock(&s.cb);
    if s.removed.load(Ordering::Acquire) {
        return;
    }
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cb(db, d)));
    drop(cb);
    if r.is_err() && s.filter != Filter::Diagnostics {
        let d = Diagnostic { kind: DiagnosticKind::Callback, tids: Vec::new(), commit: None, peer: None, detail: format!("callback panicked ({:?})", s.filter) };
        db.locked(|l| {
            l.seq += 1;
            db.inner.dispatch.send(l.seq, Msg::Event(Event::Diagnostic(d)));
        });
    }
}

/// A registration; dropping it unsubscribes (notes/api.md: RAII, no ids to remember). Off the
/// dispatcher thread, drop waits for a call in flight, so no call starts or runs after it
/// returns; except when the dropping thread holds the engine lock (inside `Osis::read` or
/// `Osis::engine`), where it cannot wait: a call may still be running then.
#[must_use = "dropping a Subscription unsubscribes at once; use detach() to keep it"]
pub struct Subscription {
    shared: Weak<Shared>,
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
        let (Some(id), Some(sh)) = (self.id, self.shared.upgrade()) else { return };
        let Some(s) = lock(&sh.registry).subs.remove(&id) else { return };
        s.removed.store(true, Ordering::Release);
        let me = std::thread::current().id();
        if !sh.on_dispatcher() && *lock(&sh.holder) != Some(me) {
            drop(lock(&s.cb));
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

    /// Stores a new value if it differs from the held one; an error counts every time.
    pub fn update(&self, v: Result<Option<Value>>) {
        let mut s = lock(&self.m);
        if v.is_ok() && s.value == v {
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
        if !s.wakers.iter().any(|w| w.will_wake(cx.waker())) {
            s.wakers.push(cx.waker().clone());
        }
        Poll::Pending
    }
}

impl<T> std::fmt::Debug for Watch<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Watch")
    }
}
