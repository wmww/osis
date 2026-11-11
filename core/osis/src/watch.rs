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
    Status,
    /// A text session's `on_merge`: called by the session, no message reaches it.
    Text,
    /// A subscription at a connected node, by its token (`port::client`), and the thing it is on.
    Port(u64, Option<Tid>),
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
    /// Which groups the thing is in.
    Groups(Tid),
    /// A roster or a key changed: `role_on`'s reach is the role graph, not one thing.
    Roles,
    /// A record of this node's alone changed: a contact imported, its saved peers.
    Local,
    /// The thing's backlinks (a reference index row naming it); with an acting actor (`true`),
    /// also what it may read: a roster or key change anywhere, as `Roles`.
    Backlinks(Tid, bool),
}

impl Watch {
    fn thing(&self) -> Option<Tid> {
        match self {
            Watch::Thing(t) | Watch::CommitsOf(t) | Watch::Groups(t) | Watch::Backlinks(t, _) => Some(*t),
            Watch::Roles | Watch::Local => None,
        }
    }
}

/// Where a subscription is found by an event: one slot per way an event names what it changed.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Slot {
    Aspect(Tid, Ak),
    Thing(Tid),
    Grants(Tid),
    Commits(Tid, Ak),
    CommitsThing(Tid),
    CommitsGroup(Tid),
    Diagnostics,
    Disputes,
    Status,
    Port(u64),
    CommitsOf(Tid),
    Groups(Tid),
    Roles,
    Local,
    Backlinks(Tid),
}

impl Filter {
    /// The slots it is found at.
    fn slots(&self) -> Vec<Slot> {
        match self {
            Filter::Aspect(t, ak, _) => vec![Slot::Aspect(*t, ak.clone())],
            Filter::Thing(t) | Filter::Due(Watch::Thing(t)) => vec![Slot::Thing(*t)],
            Filter::Grants(t) => vec![Slot::Grants(*t)],
            Filter::Commits(crate::commits::Address::Fired(t, ak) | crate::commits::Address::Versions(t, ak, _)) => vec![Slot::Commits(*t, ak.clone())],
            Filter::Commits(crate::commits::Address::Writes(s)) => match s {
                crate::commits::Scope::Thing(t) => vec![Slot::CommitsThing(*t)],
                crate::commits::Scope::Group(g) => vec![Slot::CommitsGroup(*g)],
                crate::commits::Scope::Aspects(v) => v.iter().map(|(t, ak)| Slot::Commits(*t, ak.clone())).collect(),
            },
            Filter::Diagnostics => vec![Slot::Diagnostics],
            Filter::Disputes => vec![Slot::Disputes],
            Filter::Status => vec![Slot::Status],
            Filter::Text => Vec::new(),
            Filter::Port(t, _) => vec![Slot::Port(*t)],
            Filter::Due(Watch::CommitsOf(t)) => vec![Slot::CommitsOf(*t)],
            Filter::Due(Watch::Groups(t)) => vec![Slot::Groups(*t)],
            Filter::Due(Watch::Roles) => vec![Slot::Roles],
            Filter::Due(Watch::Local) => vec![Slot::Local],
            Filter::Due(Watch::Backlinks(t, false)) => vec![Slot::Backlinks(*t)],
            Filter::Due(Watch::Backlinks(t, true)) => vec![Slot::Backlinks(*t), Slot::Roles],
        }
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
    /// A `Filter::Due` read may answer otherwise.
    Due,
}

pub(crate) enum Msg {
    Event(Event),
    Initial(u64),
    Status(Result<crate::share::Status>),
    /// A tracked read's address may have changed: for what names no event of the engine.
    Due(Watch),
    Port(u64, PortEvent),
    /// This subscription's origin moved.
    Moved(u64),
    Barrier(Sender<()>),
}

pub(crate) type Callback = Box<dyn FnMut(&Osis, Delivery) + Send>;

pub(crate) struct Sub {
    id: u64,
    /// The first sequence number it hears: a tracked read moves it past what it read.
    since: AtomicU64,
    filter: Filter,
    removed: AtomicBool,
    cb: Mutex<Callback>,
}

#[derive(Default)]
pub(crate) struct Registry {
    next: u64,
    subs: BTreeMap<u64, Arc<Sub>>,
    /// Who is found where: an event looks up the slots it names, O(log S + matched).
    index: BTreeMap<Slot, BTreeSet<u64>>,
    /// Commit listeners per thing, for the engine.
    commits_on: BTreeMap<Tid, usize>,
    /// Listeners on a group's writes: without one, an event looks up no thing's groups.
    group_listeners: usize,
}

impl Registry {
    fn insert(&mut self, s: Arc<Sub>) {
        for slot in s.filter.slots() {
            self.index.entry(slot).or_default().insert(s.id);
        }
        for t in s.filter.commit_things() {
            *self.commits_on.entry(t).or_default() += 1;
        }
        self.group_listeners += usize::from(matches!(s.filter, Filter::Commits(crate::commits::Address::Writes(crate::commits::Scope::Group(_)))));
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
        self.group_listeners -= usize::from(matches!(s.filter, Filter::Commits(crate::commits::Address::Writes(crate::commits::Scope::Group(_)))));
        Some(s)
    }

    /// The subscriptions found at `slot`.
    fn each(&self, slot: &Slot, mut hit: impl FnMut(u64)) {
        for id in self.index.get(slot).into_iter().flatten() {
            drop(osis_node::costs::span("watch: considered"));
            hit(*id);
        }
    }

    fn sub(&self, id: u64, seq: u64) -> Option<Arc<Sub>> {
        self.subs.get(&id).filter(|s| s.since.load(Ordering::Acquire) <= seq).cloned()
    }

    fn has_group_listener(&self) -> bool {
        self.group_listeners > 0
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
                Filter::Aspect(t, ..) | Filter::Thing(t) | Filter::Grants(t) => vec![(s.id, false, *t)],
                Filter::Commits(a) => a.things().into_iter().map(|t| (s.id, false, t)).collect(),
                Filter::Due(w) => w.thing().map(|t| (s.id, false, t)).into_iter().collect(),
                Filter::Port(token, Some(t)) => vec![(*token, true, *t)],
                _ => Vec::new(),
            })
            .collect()
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
        let mut r = lock(&self.shared.registry);
        r.next += 1;
        let id = r.next;
        r.insert(Arc::new(Sub { id, since: AtomicU64::new(since), filter, removed: AtomicBool::new(false), cb: Mutex::new(cb) }));
        Subscription { shared: Arc::downgrade(&self.shared), id: Some(id), port: None }
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
fn targets(sh: &Shared, db: &Osis, seq: u64, m: &Msg) -> Vec<(Arc<Sub>, Pre)> {
    if let Msg::Initial(id) = m {
        return lock(&sh.registry).subs.get(id).map(|s| (s.clone(), Pre::Ready(Delivery::Initial))).into_iter().collect();
    }
    if let Msg::Moved(id) = m {
        return lock(&sh.registry).remove(*id).map(|s| (s, Pre::Ready(Delivery::Moved))).into_iter().collect();
    }
    // the engine lock is taken before the registry's everywhere (the engine asks it under its
    // lock): a group listener's groups are read here, before the registry is locked
    let groups: HashMap<Tid, BTreeSet<Tid>> = match m {
        Msg::Event(Event::Commits(changes)) if lock(&sh.registry).has_group_listener() => {
            changes.iter().map(|c| c.tid).collect::<BTreeSet<_>>().into_iter().map(|t| (t, db.engine(|e| e.groups_of(&t)))).collect()
        }
        _ => HashMap::new(),
    };
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
        let in_group = |t: &Tid, g: Tid| *t == g || groups.get(t).is_some_and(|s| s.contains(&g));
        let mut hits: BTreeMap<u64, Vec<&osis_node::CommitChange>> = BTreeMap::new();
        let mut due = BTreeSet::new();
        for c in changes.iter() {
            let mut look = |slot: &Slot| {
                r.each(slot, |id| {
                    hits.entry(id).or_default().push(c);
                });
            };
            look(&Slot::Commits(c.tid, c.ak.clone()));
            look(&Slot::CommitsThing(c.tid));
            look(&Slot::CommitsGroup(c.tid));
            for g in groups.get(&c.tid).into_iter().flatten() {
                look(&Slot::CommitsGroup(*g));
            }
            r.each(&Slot::CommitsOf(c.tid), |id| {
                due.insert(id);
            });
        }
        for (id, cs) in hits {
            let Some(s) = r.sub(id, seq) else { continue };
            let Filter::Commits(a) = &s.filter else { continue };
            // one call per commit, however many of its parts are at the address
            let mut told: BTreeMap<CommitId, (Vec<Tid>, Option<osis_node::engine::listing::CommitRow>)> = BTreeMap::new();
            for c in cs {
                if a.holds(c.tid, &c.ak, |g| in_group(&c.tid, g)) {
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
        Msg::Event(Event::Groups(things)) => due(&things.iter().map(|t| Slot::Groups(*t)).collect::<Vec<_>>(), Delivery::Due),
        Msg::Event(Event::References(targets)) => due(&targets.iter().map(|t| Slot::Backlinks(*t)).collect::<Vec<_>>(), Delivery::Due),
        Msg::Event(Event::Diagnostic(d)) => due(&[Slot::Diagnostics], Delivery::Diagnostic(d.clone())),
        Msg::Event(Event::DisputeDetected { commit, op, holder, target, author, trust }) => {
            let side = osis_node::sides::Side { trust: *trust, chosen: false };
            let d = crate::Dispute::of(&osis_node::sides::DisputeInfo { commit: *commit, op: *op, holder: *holder, target: *target, author: *author, side: Some(side) });
            due(&[Slot::Disputes], Delivery::Dispute(d))
        }
        Msg::Event(Event::AccountDisputed { account, lines, side }) => due(&[Slot::Disputes], Delivery::Dispute(crate::Dispute::of_account(*account, lines, *side, false))),
        Msg::Status(st) => due(&[Slot::Status], Delivery::Status(st.clone())),
        Msg::Port(t, ev) => due(&[Slot::Port(*t)], Delivery::Port(ev.clone())),
        Msg::Due(Watch::Local) => due(&[Slot::Local], Delivery::Due),
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
                        let _c = osis_node::costs::span("watch: value read");
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
            drop(osis_node::costs::span("watch: dispatched"));
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
        let Some(s) = lock(&sh.registry).remove(id) else { return };
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
