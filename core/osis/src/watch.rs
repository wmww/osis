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
use osis_base::memo::Effects;
use osis_base::{Ak, Tid, Ts, Value, Time};
use crate::commit_id::CommitId;
use osis_engine::{Cause, Diagnostic, DiagnosticKind, Event, Origin as EventOrigin};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
    /// The node closure released the thing and this node forgot its copy.
    Released,
    /// After a failed write the store was read again and a commit reported failed had landed
    /// after all.
    Recovered,
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
            Cause::Released => DerivedFrom::Released,
        }
    }
}

/// One change of a value: an aspect's, or the one at the path a listener was registered at.
#[derive(Clone, Debug, PartialEq)]
pub struct Change<T> {
    /// The thing.
    pub tid: Tid,
    /// The aspect.
    pub ak: Ak,
    /// The value now, at the listener's path if it has one (`None`: absent, or not matching the
    /// type: a `Mismatch` diagnostic), or why it cannot be read (`TooLarge`, `Storage`).
    pub value: Result<Option<T>>,
    /// Why it changed.
    pub origin: Origin,
}

/// What a subscription listens to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Filter {
    /// A value inside an aspect (`on_change` at an aspect or a path), read as its `get` reads it.
    Aspect(Tid, Ak, ReadAt),
    Thing(Tid),
    Grants(Tid),
    /// Per commit: the commits listed at an address (`on_write`, `on_fire`).
    Commits(crate::commits::Address),
    Diagnostics,
    Disputes,
    /// How sync stands (`on_status_change`): `Delivery::Due` after each sync step.
    Status,
    /// A text session's `on_merge`: called by the session, no message reaches it.
    Text,
    /// A watch at another node (`port::client`): its deliveries come addressed to it
    /// (`Msg::Deliver`).
    Remote,
    /// A tracked read with no value of its own (`track`): `Delivery::Due` when `Watch` may answer
    /// otherwise.
    Due(Watch),
}

/// What may change the answer of a tracked read with no listener of its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Watch {
    /// Any aspect of the thing changed (its names, whether it holds content).
    Thing(Tid),
    /// A commit on the thing was added or judged otherwise (when it was made or last changed).
    CommitsOf(Tid),
    /// A roster or a key changed: `role_on`'s reach is the role graph, not one thing.
    Roles,
    /// The thing's backlinks (a reference index row naming it); with an acting actor (`true`),
    /// also what it may read: a roster or key change anywhere, as `Roles`.
    Backlinks(Tid, bool),
}

/// Where a subscription is found by an event: one slot per way an event names what it changed.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Slot {
    Aspect(Tid, Ak),
    Thing(Tid),
    Grants(Tid),
    Commits(Tid, Ak),
    CommitsThing(Tid),
    Diagnostics,
    Disputes,
    Status,
    CommitsOf(Tid),
    Roles,
    Backlinks(Tid),
}

impl Filter {
    /// The slots it is found at.
    fn slots(&self) -> Vec<Slot> {
        match self {
            Filter::Aspect(t, ak, _) => vec![Slot::Aspect(*t, ak.clone())],
            Filter::Thing(t) | Filter::Due(Watch::Thing(t)) => vec![Slot::Thing(*t)],
            // the roster shows only to a reader of the thing (`Reader::shows_roster`): a role change
            // anywhere may show or hide it
            Filter::Grants(t) => vec![Slot::Grants(*t), Slot::Roles],
            Filter::Commits(crate::commits::Address::Fired(t, ak) | crate::commits::Address::Versions(t, ak, _)) => vec![Slot::Commits(*t, ak.clone())],
            Filter::Commits(crate::commits::Address::Writes(s)) => match s {
                crate::commits::Scope::Thing(t) => vec![Slot::CommitsThing(*t)],
                crate::commits::Scope::Aspects(v) => v.iter().map(|(t, ak)| Slot::Commits(*t, ak.clone())).collect(),
            },
            Filter::Diagnostics => vec![Slot::Diagnostics],
            Filter::Disputes => vec![Slot::Disputes],
            Filter::Status => vec![Slot::Status],
            Filter::Text | Filter::Remote => Vec::new(),
            Filter::Due(Watch::CommitsOf(t)) => vec![Slot::CommitsOf(*t)],
            Filter::Due(Watch::Roles) => vec![Slot::Roles],
            Filter::Due(Watch::Backlinks(t, false)) => vec![Slot::Backlinks(*t)],
            Filter::Due(Watch::Backlinks(t, true)) => vec![Slot::Backlinks(*t), Slot::Roles],
        }
    }

    /// Whether a tracked read heard here is followed as an `Effects` value too (`Dispatch::follow`):
    /// one the role graph decides (`Slot::Roles`), which the clock moves with no event; a grants
    /// read is followed per thing (`Filter::Grants`).
    pub(crate) fn follows(&self) -> bool {
        matches!(self, Filter::Due(Watch::Roles | Watch::Backlinks(_, true)))
    }

    /// The things a commit listener is on, for the engine (`Engine::listen_commits`).
    fn commit_things(&self) -> Vec<Tid> {
        match self {
            Filter::Commits(a) => a.things(),
            _ => Vec::new(),
        }
    }
}

/// A value listener's memory of a value: not the value itself, whose bytes the shell need not
/// hold. `None`: an error, which is never equal.
pub(crate) type Digest = [u8; 32];

/// The digest of a read: a BLAKE3 hash of its canonical encoding.
pub(crate) fn digest(v: &Result<Option<Value>>) -> Option<Digest> {
    match v {
        Err(_) => None,
        Ok(None) => Some([0; 32]),
        Ok(Some(v)) => Some(*blake3::hash(&osis_base::cbor::encode(v)).as_bytes()),
    }
}

/// How a value watch reads its value: what its `get` reads, the same address.
#[derive(Clone)]
pub(crate) struct ReadAt(pub Arc<ReadFn>);

type ReadFn = dyn Fn(&mut crate::read::Reader<'_>) -> Result<Option<Value>> + Send + Sync;

impl ReadAt {
    pub fn new(f: impl Fn(&mut crate::read::Reader<'_>) -> Result<Option<Value>> + Send + Sync + 'static) -> ReadAt {
        ReadAt(Arc::new(f))
    }
}

impl PartialEq for ReadAt {
    fn eq(&self, o: &ReadAt) -> bool {
        Arc::ptr_eq(&self.0, &o.0)
    }
}

impl Eq for ReadAt {}

impl std::fmt::Debug for ReadAt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReadAt")
    }
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
    Commit { id: CommitId, tids: Vec<Tid>, fired: Option<osis_engine::engine::listing::CommitRow> },
    Diagnostic(Diagnostic),
    Dispute(crate::Dispute),
    /// A text session's merged text.
    Text { text: String, edits: Vec<crate::text::Splice> },
    /// A `Filter::Due` read may answer otherwise.
    Due,
    /// What a subscription at another node pushed (`port::client`).
    Remote { from: crate::share::Address, got: crate::port::client::Pushed },
    /// Anything the subscription shows may read otherwise (`Event::Reloaded`): read it all again.
    /// Only `Filter::Thing` and `Filter::Commits` hear it; the others hear their own deliveries.
    Reread,
}

pub(crate) enum Msg {
    Event(Event),
    /// Sync stepped: status may read otherwise.
    Status,
    Initial(u64),
    /// A delivery for one subscription (a watch at another node).
    Deliver(u64, Delivery),
    Barrier(Sender<()>),
}

pub(crate) type Callback = Box<dyn FnMut(&Osis, Delivery) + Send>;
/// A listener called with what it listens for.
pub(crate) type CallbackOf<T> = Box<dyn FnMut(&Osis, T) + Send>;

pub(crate) struct Sub {
    id: u64,
    /// The first sequence number it hears: a tracked read moves it past what it read.
    since: AtomicU64,
    filter: Filter,
    removed: AtomicBool,
    cb: Mutex<Callback>,
}

#[derive(Default)]
struct Registry {
    next: u64,
    subs: BTreeMap<u64, Arc<Sub>>,
    /// Who is found where: an event looks up the slots it names, O(log S + matched).
    index: BTreeMap<Slot, BTreeSet<u64>>,
    /// Commit listeners per thing, for the engine.
    commits_on: BTreeMap<Tid, usize>,
}

impl Registry {
    fn insert(&mut self, s: Arc<Sub>) {
        for slot in s.filter.slots() {
            self.index.entry(slot).or_default().insert(s.id);
        }
        for t in s.filter.commit_things() {
            *self.commits_on.entry(t).or_default() += 1;
        }
        self.subs.insert(s.id, s);
    }

    fn remove(&mut self, id: u64) -> Option<Arc<Sub>> {
        let s = self.subs.remove(&id)?;
        for slot in s.filter.slots() {
            if let Some(ids) = self.index.get_mut(&slot) {
                ids.remove(&id);
                if ids.is_empty() {
                    self.index.remove(&slot);
                }
            }
        }
        for t in s.filter.commit_things() {
            if let Some(n) = self.commits_on.get_mut(&t) {
                *n -= 1;
                if *n == 0 {
                    self.commits_on.remove(&t);
                }
            }
        }
        Some(s)
    }

    /// The subscriptions found at `slot`.
    fn each(&self, slot: &Slot, mut hit: impl FnMut(u64)) {
        for id in self.index.get(slot).into_iter().flatten() {
            drop(osis_base::costs::span("watch: considered"));
            hit(*id);
        }
    }

    fn sub(&self, id: u64, seq: u64) -> Option<Arc<Sub>> {
        self.subs.get(&id).filter(|s| s.since.load(Ordering::Acquire) <= seq).cloned()
    }

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

/// What the watch layer follows as `Effects` values, so that a change no event tells (an `until`
/// passing: a role or roster read follows the memo clock up to its next `until`,
/// `Engine::clock_next`) is told (`Dispatch::moved`): each watched roster's grants
/// (`Filter::Grants`, one key per thing watched) and each tracked read the role graph decides
/// (`Filter::follows`, one key per listener, its read in `answers`).
struct Follows {
    fx: Effects<Followed, Digest>,
    answers: HashMap<u64, Follow>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum Followed {
    Grants(Tid),
    Answer(u64),
}

/// A tracked read's answer, read again when `Follows` finds it due.
pub(crate) type Follow = Box<dyn Fn(&mut osis_engine::Engine) -> Digest + Send>;

impl Default for Follows {
    fn default() -> Follows {
        Follows { fx: Effects::new("watch: follows"), answers: HashMap::new() }
    }
}

/// State shared by the node, the dispatcher and subscriptions. Locks are taken in the order
/// engine, `follows`, `registry`.
#[derive(Default)]
pub(crate) struct Shared {
    follows: Mutex<Follows>,
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

    /// Whether callbacks run on the thread that calls `settle` (`Dispatcher::Pump`).
    pub fn pumps(&self) -> bool {
        self.wake.is_some()
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

    /// Whether a commit listener is on a thing, asked by the engine (`Engine::listen_commits`).
    pub fn commit_listened(&self) -> Arc<dyn Fn(&Tid) -> bool + Send + Sync> {
        let sh = Arc::downgrade(&self.shared);
        Arc::new(move |t| sh.upgrade().is_some_and(|sh| lock(&sh.registry).commits_on.contains_key(t)))
    }

    /// Live registrations (`Internals::watches`).
    pub fn registrations(&self) -> usize {
        lock(&self.shared.registry).subs.len()
    }

    /// Registers a callback for messages from sequence `since` on.
    pub fn register(&self, since: u64, filter: Filter, cb: Callback) -> Subscription {
        let mut follows = lock(&self.shared.follows);
        let mut r = lock(&self.shared.registry);
        r.next += 1;
        let id = r.next;
        if let Filter::Grants(t) = filter {
            follows.fx.want(Followed::Grants(t));
        }
        r.insert(Arc::new(Sub { id, since: AtomicU64::new(since), filter, removed: AtomicBool::new(false), cb: Mutex::new(cb) }));
        Subscription { shared: Arc::downgrade(&self.shared), id: Some(id) }
    }

    /// Follows tracked read `id`'s answer (`Filter::follows`), read by `read`, under the engine
    /// lock of the read it goes with: its first `moved` reads it, unchanged since.
    pub fn follow(&self, id: u64, read: Follow) {
        let mut f = lock(&self.shared.follows);
        f.fx.want(Followed::Answer(id));
        f.answers.insert(id, read);
    }

    /// What `Follows` follows that reads otherwise since last asked, under the engine lock: the
    /// watched rosters, and the tracked reads, a change told by no event moved too (an `until`
    /// passing). Work in proportion to what moved what they read; a key just followed is read,
    /// not told.
    pub fn moved(&self, e: &mut osis_engine::Engine) -> (Vec<Tid>, Vec<u64>) {
        let mut guard = lock(&self.shared.follows);
        let f = &mut *guard;
        let (mut things, mut ids) = (Vec::new(), Vec::new());
        for k in f.fx.due() {
            let moved = match &k {
                Followed::Grants(t) => f.fx.settle(&k, || crate::track::answer_digest(&crate::read::Reader { e: &mut *e, limit: 0, actor: None }.grants(*t))),
                Followed::Answer(id) => match f.answers.get(id) {
                    Some(read) => f.fx.settle(&k, || read(&mut *e)),
                    None => None,
                },
            };
            if let Some((Some(_), _)) = moved {
                match k {
                    Followed::Grants(t) => things.push(t),
                    Followed::Answer(id) => ids.push(id),
                }
            }
        }
        (things, ids)
    }

    /// Whether subscription `id` is still registered.
    pub fn registered(&self, id: u64) -> bool {
        lock(&self.shared.registry).subs.contains_key(&id)
    }

    /// Whether a status listener is registered (sync steps tell it, `Msg::Status`).
    pub fn status_listened(&self) -> bool {
        lock(&self.shared.registry).index.contains_key(&Slot::Status)
    }

    /// Subscription `id` hears messages from sequence `since` on (a tracked read, read again).
    pub fn since(&self, id: u64, since: u64) {
        if let Some(s) = lock(&self.shared.registry).subs.get(&id) {
            s.since.store(since, Ordering::Release);
        }
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

fn origin_of(id: CommitId, from: EventOrigin, actor: Tid, ts: Ts, received: Time) -> Origin {
    let i = Stamp::new(id, actor, ts, received);
    if from == EventOrigin::Local { Origin::Local(i) } else { Origin::Remote(i) }
}

/// The aspects an event changed, with its origin.
fn aspect_event(m: &Msg) -> Option<(&[(Tid, Ak)], Origin)> {
    match m {
        Msg::Event(Event::Applied { id, origin, actor, ts, received, changed, .. }) => Some((changed, origin_of(CommitId(*id), *origin, *actor, *ts, *received))),
        Msg::Event(Event::Ephemeral { id, origin, actor, ts, received, changed, .. }) => Some((changed, origin_of(CommitId(*id), *origin, *actor, *ts, *received))),
        Msg::Event(Event::Changed { cause, changed }) => Some((changed, Origin::Derived((*cause).into()))),
        _ => None,
    }
}

/// What a message delivers to the subscriptions found at it (`usize::MAX`: once per message,
/// `Delivery::Due`).
const ONCE: usize = usize::MAX;

/// A call before its value is read.
enum Pre {
    Aspect { tid: Tid, ak: Ak, origin: Origin },
    Ready(Delivery),
}

/// Which subscriptions a message reaches: the slots it names looked up in the registry, in
/// subscription order, O(log S + matched).
fn targets(sh: &Shared, _db: &Osis, seq: u64, m: &Msg) -> Vec<(Arc<Sub>, Pre)> {
    if let Msg::Initial(id) = m {
        return lock(&sh.registry).subs.get(id).map(|s| (s.clone(), Pre::Ready(Delivery::Initial))).into_iter().collect();
    }
    if let Msg::Deliver(id, d) = m {
        return lock(&sh.registry).sub(*id, seq).map(|s| (s, Pre::Ready(d.clone()))).into_iter().collect();
    }
    let r = lock(&sh.registry);
    let due = |slots: &[Slot], d: Delivery| {
        let mut ids = BTreeSet::new();
        for slot in slots {
            r.each(slot, |id| {
                ids.insert(id);
            });
        }
        ids.into_iter().filter_map(|id| r.sub(id, seq)).map(|s| (s, Pre::Ready(d.clone()))).collect()
    };
    if let Msg::Event(Event::Reloaded) = m {
        // a commit answered `Err` may have landed: every subscription on what the store holds reads
        // again, each as its own deliveries read
        let origin = Origin::Derived(DerivedFrom::Recovered);
        return r
            .subs
            .keys()
            .filter_map(|id| r.sub(*id, seq))
            .filter_map(|s| {
                let pre = match &s.filter {
                    Filter::Aspect(t, ak, _) => Pre::Aspect { tid: *t, ak: ak.clone(), origin },
                    Filter::Grants(_) => Pre::Ready(Delivery::Grants),
                    Filter::Due(_) => Pre::Ready(Delivery::Due),
                    Filter::Thing(_) | Filter::Commits(_) => Pre::Ready(Delivery::Reread),
                    // events, not reads (status follows every change on its own); a session's
                    // merge hears its aspect's; another node's store did not move
                    Filter::Diagnostics | Filter::Disputes | Filter::Text | Filter::Remote => return None,
                    Filter::Status => Pre::Ready(Delivery::Due),
                };
                Some((s, pre))
            })
            .collect();
    }
    if let Some((changed, origin)) = aspect_event(m) {
        // a role change told by no `Event::Roster` (an expiry, a purge, lost access): its grants too
        let derived = matches!(m, Msg::Event(Event::Changed { .. }));
        let mut grants = BTreeSet::new();
        let mut hits: BTreeSet<(u64, usize)> = BTreeSet::new();
        for (i, (t, ak)) in changed.iter().enumerate() {
            r.each(&Slot::Aspect(*t, ak.clone()), |id| {
                hits.insert((id, i));
            });
            r.each(&Slot::Thing(*t), |id| {
                let once = r.subs.get(&id).is_some_and(|s| matches!(s.filter, Filter::Due(_)));
                hits.insert((id, if once { ONCE } else { i }));
            });
            if osis_schema::core_types::is_role_class(ak.as_str()) {
                r.each(&Slot::Roles, |id| {
                    hits.insert((id, ONCE));
                });
                if derived {
                    r.each(&Slot::Grants(*t), |id| {
                        grants.insert(id);
                    });
                }
            }
        }
        let told = grants.into_iter().filter_map(|id| r.sub(id, seq)).map(|s| (s, Pre::Ready(Delivery::Grants)));
        return hits
            .into_iter()
            .filter_map(|(id, i)| {
                let s = r.sub(id, seq)?;
                let pre = match changed.get(i) {
                    Some((t, ak)) => Pre::Aspect { tid: *t, ak: ak.clone(), origin },
                    None => Pre::Ready(Delivery::Due),
                };
                Some((s, pre))
            })
            .chain(told)
            .collect();
    }
    if let Msg::Event(Event::Commits(changes)) = m {
        let mut out = Vec::new();
        let mut hits: BTreeMap<u64, Vec<&osis_engine::CommitChange>> = BTreeMap::new();
        let mut due = BTreeSet::new();
        for c in changes.iter() {
            let mut look = |slot: &Slot| {
                r.each(slot, |id| {
                    hits.entry(id).or_default().push(c);
                });
            };
            look(&Slot::Commits(c.tid, c.ak.clone()));
            look(&Slot::CommitsThing(c.tid));
            r.each(&Slot::CommitsOf(c.tid), |id| {
                due.insert(id);
            });
        }
        for (id, cs) in hits {
            let Some(s) = r.sub(id, seq) else { continue };
            let Filter::Commits(a) = &s.filter else { continue };
            // one call per commit, however many of its parts are at the address
            let mut told: BTreeMap<CommitId, (Vec<Tid>, Option<osis_engine::engine::listing::CommitRow>)> = BTreeMap::new();
            for c in cs {
                if a.holds(c.tid, &c.ak) {
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
        out.extend(due.into_iter().filter_map(|id| r.sub(id, seq)).map(|s| (s, Pre::Ready(Delivery::Due))));
        return out;
    }
    match m {
        Msg::Event(Event::Roster { thing } | Event::Created { thing }) => {
            let mut out: Vec<_> = due(&[Slot::Grants(*thing)], Delivery::Grants);
            out.extend(due(&[Slot::Roles], Delivery::Due));
            out
        }
        Msg::Event(Event::References(targets)) => due(&targets.iter().map(|t| Slot::Backlinks(*t)).collect::<Vec<_>>(), Delivery::Due),
        Msg::Event(Event::Diagnostic(d)) => due(&[Slot::Diagnostics], Delivery::Diagnostic(d.clone())),
        Msg::Status => due(&[Slot::Status], Delivery::Due),
        Msg::Event(Event::DisputeDetected { commit, op, holder, target, author, trust }) => {
            let side = osis_engine::sides::Side { trust: *trust, chosen: false };
            let d = crate::Dispute::of(&osis_engine::sides::DisputeInfo { commit: *commit, op: *op, holder: *holder, target: *target, author: *author, side: Some(side) });
            due(&[Slot::Disputes], Delivery::Dispute(d))
        }
        Msg::Event(Event::AccountDisputed { account, lines, side }) => due(&[Slot::Disputes], Delivery::Dispute(crate::Dispute::of_account(*account, lines, *side, false))),
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
                    let value = {
                        let _c = osis_base::costs::span("watch: value read");
                        match &s.filter {
                            Filter::Aspect(_, _, read) => db.read_with(|r| read.0(r), || buf.extend(rx.try_iter())),
                            _ => db.read_with(|r| r.value(tid, &ak), || buf.extend(rx.try_iter())),
                        }
                    };
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
            drop(osis_base::costs::span("watch: dispatched"));
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
/// let db = osis::Osis::create(osis::Store::Memory(osis::MemStore::new()), osis::Config::default()).unwrap();
/// db.on_diagnostic(|_, _| {}).unwrap();
/// ```
// The exception: a thread holding the engine lock (inside `Internals::engine`) cannot wait, so a
// call may still be running then.
#[must_use = "dropping a Subscription unsubscribes at once; use detach() to keep it"]
pub struct Subscription {
    shared: Weak<Shared>,
    id: Option<u64>,
}

impl Subscription {
    /// Keeps the subscription for the node's life.
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
        let mut follows = lock(&sh.follows);
        let mut r = lock(&sh.registry);
        let Some(s) = r.remove(id) else { return };
        if let Filter::Grants(t) = s.filter
            && !r.index.contains_key(&Slot::Grants(t))
        {
            follows.fx.unwant(&Followed::Grants(t));
        }
        if follows.answers.remove(&id).is_some() {
            follows.fx.unwant(&Followed::Answer(id));
        }
        drop((r, follows));
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
