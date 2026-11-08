//! Watching (notes/api.md Watching): one dispatcher per node runs every callback, in
//! commit order, after the commit is durable, never under a lock. Its driver is a thread osis
//! starts (`Dispatcher::Thread`) or whichever thread calls `Osis::settle` (`Dispatcher::Pump`,
//! woken by the app's callback); both run the same `Pump::step`. Engine events are drained into
//! the dispatcher's queue under the engine lock, each with a sequence number; a subscription
//! ignores messages queued before it registered, so a watch taken atomically with the current
//! value misses nothing and sees nothing twice. A call reads the aspect's latest state
//! (coalescing: later queued events for that aspect are folded in, and the call carries the
//! origin of the newest of them); a value equal to the last one delivered is skipped, an error
//! never is. A panicking callback becomes a diagnostic; the dispatcher lives on.

use crate::error::{Error, Result};
use crate::handle::{Inner, Osis};
use crate::read::Stamp;
use osis_base::{Ak, Tid, Ts, Value, Time};
use crate::commit_id::CommitId;
use osis_node::{Cause, Diagnostic, DiagnosticKind, Event, Origin as EventOrigin};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::thread::ThreadId;

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Why a watched value changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// The first call of `on_change`, with the value at registration.
    Initial,
    /// A commit made on this node.
    Local(Stamp),
    /// A commit received from another node.
    Remote(Stamp),
    /// No new commit: something else changed what the aspect reads.
    Derived(DerivedFrom),
}

/// What changed a read when no new commit did (`Origin::Derived`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DerivedFrom {
    /// A write was found valid or invalid after all, as its author's roles became known.
    ValidityChanged,
    /// A write expired.
    Expired,
    /// A write was purged.
    Purged,
    /// More of an earlier commit arrived: another part of it, or a large value a read had missed.
    Arrived,
    /// This node lost read access.
    LostAccess,
}

#[doc(hidden)]
impl From<Cause> for DerivedFrom {
    fn from(c: Cause) -> DerivedFrom {
        match c {
            Cause::Validity => DerivedFrom::ValidityChanged,
            Cause::Expiry => DerivedFrom::Expired,
            Cause::Purge => DerivedFrom::Purged,
            Cause::LateDelta | Cause::Fetched => DerivedFrom::Arrived,
            Cause::LostAccess => DerivedFrom::LostAccess,
        }
    }
}

/// One change of an aspect.
#[derive(Clone, Debug, PartialEq)]
pub struct Change<T> {
    /// The thing.
    pub tid: Tid,
    /// The aspect.
    pub ak: Ak,
    /// The value now (`None`: absent, or not matching the key's type: a `Mismatch`
    /// diagnostic), or why it cannot be read (`TooLarge`, `Storage`).
    pub value: Result<Option<T>>,
    /// Why it changed.
    pub origin: Origin,
}

/// What a subscription listens to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Filter {
    Aspect(Tid, Ak),
    Thing(Tid),
    Grants(Tid),
    /// Per commit: the commits listed at an address (`on_write`, `on_fire`).
    Commits(crate::commits::Address),
    Diagnostics,
    Disputes,
    Status,
    /// A text session's `on_remote`: called by the session, no message reaches it.
    Text,
    /// A subscription at a connected node, by its token (`port::client`), and the thing it is on.
    Port(u64, Option<Tid>),
}

/// What a subscription at the connected node delivers (`port::client`), in wire order.
#[derive(Clone, Debug)]
pub(crate) enum PortEvent {
    /// The Sub's reply: the initial value.
    Initial(Value),
    Notify(osis_proto::Payload),
    /// The connection is gone: nothing more until a reconnect's `Initial`; none for a
    /// subscription that ended.
    Closed,
}

/// What a callback is called with.
#[derive(Clone, Debug)]
pub(crate) enum Delivery {
    Initial,
    /// `value` is the aspect read when the call was prepared; `origin` the last event whose
    /// effect it shows.
    Aspect { tid: Tid, ak: Ak, origin: Origin, value: Result<Option<Value>> },
    Grants,
    /// This commit may read otherwise at the filter's address; `fired`: an ephemeral signal's
    /// commit, which nobody holds, as it arrived.
    /// `tids`: the things of its parts at the address.
    Commit { id: CommitId, tids: Vec<Tid>, fired: Option<osis_node::engine::listing::CommitRow> },
    Diagnostic(Diagnostic),
    Dispute(crate::Dispute),
    Status(Result<crate::share::Status>),
    Port(PortEvent),
    /// A text session's merged text.
    Text { text: String, edits: Vec<crate::text::Splice> },
    /// The group's origin moved (`Osis::group_source`): the last call of this subscription, which
    /// would otherwise go silent.
    Moved,
}

pub(crate) enum Msg {
    Event(Event),
    Initial(u64),
    Status(Result<crate::share::Status>),
    Port(u64, PortEvent),
    /// This subscription's origin moved.
    Moved(u64),
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

/// Where watch callbacks run (`AppConfig::dispatch`).
#[derive(Clone, Default)]
pub enum Dispatcher {
    /// On a dispatcher thread the node starts (the default).
    #[default]
    Thread,
    /// On the thread that calls `Osis::settle` (an app's UI thread), which then runs every
    /// callback due. `wake` is called once when callbacks become due after the last `settle`
    /// began, on whatever thread queued them, after the node lock is released: it should
    /// only arrange for a `settle` soon (post an event to the UI loop).
    Pump(Arc<dyn Fn() + Send + Sync>),
}

impl std::fmt::Debug for Dispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Dispatcher::Thread => "Thread",
            Dispatcher::Pump(_) => "Pump",
        })
    }
}

/// State shared by the node, the dispatcher and subscriptions.
#[derive(Default)]
pub(crate) struct Shared {
    registry: Mutex<Registry>,
    /// The thread holding the engine lock, if any (a subscription dropped there must not wait
    /// for an in-flight call: that call may be waiting for the engine lock).
    pub holder: Mutex<Option<ThreadId>>,
    /// The thread running callbacks: the dispatcher thread, or the one inside a pumping
    /// `settle`.
    thread: Mutex<Option<ThreadId>>,
}

impl Shared {
    pub(crate) fn on_dispatcher(&self) -> bool {
        *lock(&self.thread) == Some(std::thread::current().id())
    }
}

/// The dispatcher's sending side, kept by the node, with the queue until a thread takes it
/// (`Dispatcher::Thread`) or for `settle` to pump (`Dispatcher::Pump`).
pub(crate) struct Dispatch {
    tx: Sender<(u64, Msg)>,
    pub shared: Arc<Shared>,
    pump: Mutex<Option<Pump>>,
    /// `Dispatcher::Pump`'s wake, whether it was owed since the last pump began, and whether
    /// it is owed but not yet called (`send` runs under the engine lock; `wake` after it).
    wake: Option<Arc<dyn Fn() + Send + Sync>>,
    due: AtomicBool,
    owed: AtomicBool,
}

type Queue = Receiver<(u64, Msg)>;

impl Dispatch {
    pub fn new(mode: &Dispatcher) -> Dispatch {
        let (tx, rx) = channel();
        let wake = match mode {
            Dispatcher::Thread => None,
            Dispatcher::Pump(w) => Some(w.clone()),
        };
        Dispatch { tx, shared: Arc::default(), pump: Mutex::new(Some(Pump::new(rx))), wake, due: AtomicBool::new(false), owed: AtomicBool::new(false) }
    }

    /// With `Dispatcher::Thread`, starts the dispatcher thread; it runs until the node
    /// closes.
    pub fn start(&self, db: Weak<Inner>) -> Result<()> {
        if self.wake.is_some() {
            return Ok(());
        }
        let Some(mut p) = lock(&self.pump).take() else { return Ok(()) };
        let sh = self.shared.clone();
        // the thread records itself before its first message, so no call runs unrecognized
        let (ready, started) = channel();
        std::thread::Builder::new()
            .name("osis-dispatch".into())
            .spawn(move || {
                *lock(&sh.thread) = Some(std::thread::current().id());
                let _ = ready.send(());
                while p.step(&sh, &db, true) {}
            })
            .map_err(|e| Error::Storage(e.to_string()))?;
        let _ = started.recv();
        Ok(())
    }

    /// Queues a message with sequence number `seq` (taken under the engine lock; the lock's
    /// holder calls `wake` once it released the lock).
    pub fn send(&self, seq: u64, m: Msg) {
        let _ = self.tx.send((seq, m));
        if self.wake.is_some() && !self.due.swap(true, Ordering::AcqRel) {
            self.owed.store(true, Ordering::Release);
        }
    }

    /// Calls `Dispatcher::Pump`'s wake if a `send` owes it; called with the engine lock released.
    pub fn wake(&self) {
        if let Some(w) = &self.wake
            && self.owed.swap(false, Ordering::AcqRel)
        {
            w();
        }
    }

    /// What live subscriptions are on: (id or token, whether a token, thing).
    pub fn subs_on(&self) -> Vec<(u64, bool, Tid)> {
        lock(&self.shared.registry)
            .subs
            .values()
            .flat_map(|s| match &s.filter {
                Filter::Aspect(t, _) | Filter::Thing(t) | Filter::Grants(t) => vec![(s.id, false, *t)],
                Filter::Commits(a) => a.things().into_iter().map(|t| (s.id, false, t)).collect(),
                Filter::Port(token, Some(t)) => vec![(*token, true, *t)],
                _ => Vec::new(),
            })
            .collect()
    }

    /// Live registrations (`Internals::watches`).
    pub fn registrations(&self) -> usize {
        lock(&self.shared.registry).subs.len()
    }

    /// Registers a callback for messages from sequence `since` on.
    pub fn register(&self, since: u64, filter: Filter, cb: Callback) -> Subscription {
        let mut r = lock(&self.shared.registry);
        r.next += 1;
        let id = r.next;
        r.subs.insert(id, Arc::new(Sub { id, since, filter, removed: AtomicBool::new(false), cb: Mutex::new(cb) }));
        Subscription { shared: Arc::downgrade(&self.shared), id: Some(id), port: None }
    }

    /// Calls subscription `id` on this thread, which must be running callbacks.
    pub fn call_now(&self, db: &Osis, id: u64, d: Delivery) {
        let s = lock(&self.shared.registry).subs.get(&id).cloned();
        if let Some(s) = s {
            call(db, &s, d);
        }
    }

    /// Returns once every message queued so far has been dispatched: waits for the thread,
    /// or pumps on this one (after another thread's pump in progress). At once on the
    /// dispatcher.
    pub fn settle(&self, db: Weak<Inner>) {
        if self.shared.on_dispatcher() {
            return;
        }
        if self.wake.is_none() {
            let (tx, rx) = channel();
            if self.tx.send((0, Msg::Barrier(tx))).is_ok() {
                let _ = rx.recv();
            }
            return;
        }
        let mut q = lock(&self.pump);
        let Some(p) = q.as_mut() else { return };
        // a guard: a panic past `call`'s catch leaves no thread marked as the dispatcher
        struct Pumping<'a>(&'a Shared);
        impl Drop for Pumping<'_> {
            fn drop(&mut self) {
                *lock(&self.0.thread) = None;
            }
        }
        *lock(&self.shared.thread) = Some(std::thread::current().id());
        let _g = Pumping(&self.shared);
        // reset before draining: a message queued after the drain's last look wakes again
        self.due.swap(false, Ordering::AcqRel);
        while p.step(&self.shared, &db, false) {}
    }
}

fn origin_of(id: CommitId, from: EventOrigin, node: Tid, actor: Tid, ts: Ts, received: Time) -> Origin {
    let i = Stamp::new(id, actor, node, ts, received);
    if from == EventOrigin::Local { Origin::Local(i) } else { Origin::Remote(i) }
}

/// The aspects an event changed, with its origin.
fn aspect_event(m: &Msg) -> Option<(&[(Tid, Ak)], Origin)> {
    match m {
        Msg::Event(Event::Applied { id, origin, author, actor, ts, received, changed, .. }) => Some((changed, origin_of(CommitId(*id), *origin, *author, *actor, *ts, *received))),
        Msg::Event(Event::Ephemeral { id, origin, author, actor, ts, received, changed, .. }) => Some((changed, origin_of(CommitId(*id), *origin, *author, *actor, *ts, *received))),
        Msg::Event(Event::Changed { cause, changed }) => Some((changed, Origin::Derived((*cause).into()))),
        _ => None,
    }
}

/// A call before its value is read.
enum Pre {
    Aspect { tid: Tid, ak: Ak, origin: Origin },
    Ready(Delivery),
}

/// Which subscriptions a message reaches.
fn targets(sh: &Shared, db: &Osis, seq: u64, m: &Msg) -> Vec<(Arc<Sub>, Pre)> {
    if let Msg::Initial(id) = m {
        return lock(&sh.registry).subs.get(id).map(|s| (s.clone(), Pre::Ready(Delivery::Initial))).into_iter().collect();
    }
    if let Msg::Moved(id) = m {
        return lock(&sh.registry).subs.remove(id).map(|s| (s, Pre::Ready(Delivery::Moved))).into_iter().collect();
    }
    let live: Vec<Arc<Sub>> = lock(&sh.registry).subs.values().filter(|s| s.since <= seq).cloned().collect();
    let to = |f: &dyn Fn(&Filter) -> bool, d: Delivery| live.iter().filter(|s| f(&s.filter)).map(|s| (s.clone(), Pre::Ready(d.clone()))).collect();
    if let Some((changed, origin)) = aspect_event(m) {
        let mut out = Vec::new();
        for s in &live {
            let ft = match &s.filter {
                Filter::Aspect(t, _) | Filter::Thing(t) => *t,
                _ => continue,
            };
            for (t, ak) in changed {
                let hit = ft == *t
                    && match &s.filter {
                        Filter::Aspect(_, fak) => fak == ak,
                        _ => true,
                    };
                if hit {
                    out.push((s.clone(), Pre::Aspect { tid: *t, ak: ak.clone(), origin }));
                }
            }
        }
        return out;
    }
    if let Msg::Event(Event::Commits(changes)) = m {
        let mut out = Vec::new();
        for s in &live {
            let Filter::Commits(a) = &s.filter else { continue };
            // one call per commit, however many of its parts are at the address
            let mut told: BTreeMap<CommitId, (Vec<Tid>, Option<osis_node::engine::listing::CommitRow>)> = BTreeMap::new();
            for c in changes.iter() {
                if a.holds(c.tid, &c.ak, |g| c.tid == g || db.engine(|e| e.groups_of(&c.tid).contains(&g))) {
                    let x = told.entry(CommitId(c.id)).or_default();
                    if !x.0.contains(&c.tid) {
                        x.0.push(c.tid);
                    }
                    if x.1.is_none() {
                        x.1 = c.fired.clone();
                    }
                }
            }
            out.extend(told.into_iter().map(|(id, (tids, fired))| (s.clone(), Pre::Ready(Delivery::Commit { id, tids, fired }))));
        }
        return out;
    }
    match m {
        Msg::Event(Event::Roster { thing }) => to(&|f| *f == Filter::Grants(*thing), Delivery::Grants),
        Msg::Event(Event::Diagnostic(d)) => to(&|f| *f == Filter::Diagnostics, Delivery::Diagnostic(d.clone())),
        Msg::Event(Event::DisputeDetected { commit, op, holder, target, author, trust }) => {
            let side = osis_node::sides::Side { trust: *trust, chosen: false };
            let d = crate::Dispute::of(&osis_node::sides::DisputeInfo { commit: *commit, op: *op, holder: *holder, target: *target, author: *author, side: Some(side) });
            to(&|f| *f == Filter::Disputes, Delivery::Dispute(d))
        }
        Msg::Status(st) => to(&|f| *f == Filter::Status, Delivery::Status(st.clone())),
        Msg::Port(t, ev) => to(&|f| matches!(f, Filter::Port(x, _) if x == t), Delivery::Port(ev.clone())),
        _ => Vec::new(),
    }
}

/// The dispatcher's state: the queue, the messages taken from it early (a coalesced read shows
/// their effect), and what coalesced calls already showed.
pub(crate) struct Pump {
    rx: Queue,
    buf: VecDeque<(u64, Msg)>,
    // (subscription, tid, ak) -> last sequence number a coalesced call already showed
    covered: HashMap<(u64, Tid, Ak), u64>,
}

impl Pump {
    fn new(rx: Queue) -> Pump {
        Pump { rx, buf: VecDeque::new(), covered: HashMap::new() }
    }

    /// Dispatches the next message, waiting for one if `wait`; `false` when there was none
    /// (or the node closed).
    fn step(&mut self, sh: &Shared, db: &Weak<Inner>, wait: bool) -> bool {
        let next = match self.buf.pop_front() {
            Some(x) => Some(x),
            None if wait => self.rx.recv().ok(),
            None => self.rx.try_recv().ok(),
        };
        let Some((seq, m)) = next else { return false };
        if let Msg::Barrier(done) = m {
            let _ = done.send(());
            return true;
        }
        let Some(inner) = db.upgrade() else { return true };
        let db = Osis::internal(inner);
        self.covered.retain(|_, c| *c >= seq);
        for (s, pre) in targets(sh, &db, seq, &m) {
            let d = match pre {
                Pre::Ready(d) => d,
                Pre::Aspect { tid, ak, mut origin } => {
                    let key = (s.id, tid, ak.clone());
                    if self.covered.contains_key(&key) {
                        continue;
                    }
                    // read under the engine lock, queueing every event whose effect it shows;
                    // the call carries the origin of the newest such event for this aspect
                    let (rx, buf) = (&self.rx, &mut self.buf);
                    let value = db.value_with(tid, &ak, || buf.extend(rx.try_iter()));
                    let mut last = seq;
                    for (s2, m2) in &self.buf {
                        if let Some((changed, src)) = aspect_event(m2)
                            && changed.iter().any(|(t, a)| *t == tid && *a == ak)
                        {
                            origin = src;
                            last = *s2;
                        }
                    }
                    if last > seq {
                        self.covered.insert(key, last);
                    }
                    Delivery::Aspect { tid, ak, origin, value }
                }
            };
            call(&db, &s, d);
        }
        true
    }
}

/// Runs one callback; a panic is caught and reported as a diagnostic, and dispatch goes on.
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

/// A registered callback; dropping this unsubscribes. Off the dispatcher thread, drop waits for a call
/// in flight, so no call starts or runs after it returns. Dropping it at once is a lint:
/// ```compile_fail
/// #![deny(unused_must_use)]
/// let db = osis::Osis::create(osis::Store::Memory(osis::MemStore::new()), &[], osis::Config::default()).unwrap();
/// db.on_diagnostic(|_, _| {}).unwrap();
/// ```
// The exception: a thread holding the engine lock (inside `Internals::engine`) cannot wait, so a
// call may still be running then.
#[must_use = "dropping a Subscription unsubscribes at once; use detach() to keep it"]
pub struct Subscription {
    shared: Weak<Shared>,
    id: Option<u64>,
    /// A subscription at the connected node: unsubscribed there on drop.
    pub(crate) port: Option<(Weak<crate::port::client::Connection>, u64)>,
}

impl Subscription {
    /// Keeps the subscription for the node's life.
    pub fn detach(mut self) {
        self.id = None;
        self.port = None;
    }

    pub(crate) fn id(&self) -> Option<u64> {
        self.id
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        if let Some((r, token)) = self.port.take()
            && let Some(r) = r.upgrade()
        {
            r.unsub(token);
        }
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
