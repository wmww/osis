//! Tracked reads (notes/api.md Watching): a handle made by `Osis::tracking` keeps, in its
//! `ReadSet`, one listener per address it read, taken with the read under the node lock, so no
//! write falls between them on any dispatcher. A listener is the read's own (`on_change`,
//! `on_write`, ...) or, for a read with no public listener, an internal one (`Filter::Due`). It
//! remembers a digest of the last answer read and calls the set's `on_change` once when an event
//! after that read leaves its address reading otherwise, then waits for the next read.

use crate::commits::Address;
use crate::CommitId;
use crate::error::{Error, Result};
use crate::handle::{Locked, Osis, ReadOnly};
use crate::read::Reader;
use crate::sources::Source;
use crate::watch::{Callback, Delivery, DerivedFrom, Digest, Filter, Origin, ReadAt, Subscription, Watch, digest, lock};
use osis_base::{Ak, Tid, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

/// What a tracking handle has read (`Osis::tracking`): one listener per address read since the
/// last `sweep`, each calling `on_change` when its address reads otherwise than it did when read.
/// `on_change` runs on the dispatcher, with the node handle, like every callback.
pub struct ReadSet(pub(crate) Arc<SetInner>);

pub(crate) struct SetInner {
    on_change: Box<dyn Fn(&Osis) + Send + Sync>,
    listeners: Mutex<HashMap<String, Listener>>,
    pass: AtomicU64,
}

struct Listener {
    sub: Subscription,
    gate: Arc<Gate>,
    /// The pass it was last read in.
    pass: u64,
    /// Reads of it in that pass (a read of one address twice: `internals::read_counts`).
    reads: u32,
}

impl Listener {
    fn read(&mut self, pass: u64) {
        self.reads = if self.pass == pass { self.reads + 1 } else { 1 };
        self.pass = pass;
    }
}

/// What a listener compares with, and whether it is waiting to be read again.
struct Gate {
    last: Mutex<Option<Digest>>,
    armed: AtomicBool,
    /// Its subscription ended or errored (the source moved, a connection lost): told once, and
    /// replaced at the next read.
    gone: AtomicBool,
    /// A connected node's subscription has called once (a call with no origin to say it is initial).
    called: AtomicBool,
}

impl Gate {
    fn new(last: Option<Digest>) -> Arc<Gate> {
        Arc::new(Gate { last: Mutex::new(last), armed: AtomicBool::new(true), gone: AtomicBool::new(false), called: AtomicBool::new(false) })
    }

    fn fire(&self, set: &Weak<SetInner>, db: &Osis) {
        if self.armed.swap(false, Ordering::AcqRel)
            && let Some(s) = set.upgrade()
        {
            (s.on_change)(db);
        }
    }

    /// The subscription ended (`Delivery::Moved`, a connected node's error): nothing more comes.
    fn ended(&self, set: &Weak<SetInner>, db: &Osis) {
        self.gone.store(true, Ordering::Release);
        self.fire(set, db);
    }

    fn change(&self, set: &Weak<SetInner>, db: &Osis, value_err: bool, initial: bool) {
        if value_err {
            return self.ended(set, db);
        }
        if !initial || self.gone.load(Ordering::Acquire) {
            self.fire(set, db);
        }
    }
}

impl ReadSet {
    /// A new set; `on_change` is called when something read through it reads otherwise.
    pub fn new(on_change: impl Fn(&Osis) + Send + Sync + 'static) -> ReadSet {
        ReadSet(Arc::new(SetInner { on_change: Box::new(on_change), listeners: Mutex::default(), pass: AtomicU64::new(0) }))
    }

    /// Drops the listeners not read since the last `sweep` and starts anew: what the set reads
    /// from now on is what it listens to.
    pub fn sweep(&self) {
        let pass = self.0.pass.fetch_add(1, Ordering::AcqRel);
        let mut g = lock(&self.0.listeners);
        let old: Vec<String> = g.iter().filter(|(_, l)| l.pass != pass).map(|(k, _)| k.clone()).collect();
        let dropped: Vec<Listener> = old.into_iter().filter_map(|k| g.remove(&k)).collect();
        drop(g);
        drop(dropped);
    }
}

impl ReadSet {
    /// Every address listened to and how often the last pass read it: test harnesses' view
    /// (`internals::read_counts`).
    pub(crate) fn counts(&self) -> Vec<(String, u32)> {
        lock(&self.0.listeners).iter().map(|(k, l)| (k.clone(), l.reads)).collect()
    }
}

impl std::fmt::Debug for ReadSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ReadSet({})", lock(&self.0.listeners).len())
    }
}

impl Osis {
    /// A read-only handle every read through which also keeps a listener in `set`, taken with the
    /// read: nothing written between reading and listening is missed, on any dispatcher. A
    /// listener already in the set is reused. Reads whose answer the node cannot be told of
    /// changing (at another node) fail `Unsupported`; reads with nothing to listen to are not on
    /// a `ReadOnly` at all.
    pub fn tracking(&self, set: &ReadSet) -> ReadOnly {
        let mut o = ReadOnly::clone(self);
        o.tracking = Some(set.0.clone());
        o
    }
}

impl ReadOnly {

    /// `Unsupported` on a tracking handle: this read has no listener.
    pub(crate) fn untrackable(&self, what: &str) -> Result<()> {
        if self.tracking.is_some() {
            return Err(Error::Unsupported(format!("{what} cannot be tracked")));
        }
        Ok(())
    }

    /// Registers (or re-arms) the set's listener for `key` under the node lock `l` taken by the
    /// read. `make` gives its filter and callback, once.
    fn track_in(&self, l: &mut Locked, set: &Arc<SetInner>, key: String, last: Option<Digest>, make: impl FnOnce(Arc<Gate>) -> (Filter, Callback)) {
        let pass = set.pass.load(Ordering::Acquire);
        let since = l.seq + 1;
        let mut g = lock(&set.listeners);
        if let Some(li) = g.get_mut(&key).filter(|li| !li.gate.gone.load(Ordering::Acquire)) {
            *lock(&li.gate.last) = last;
            li.gate.armed.store(true, Ordering::Release);
            if let Some(id) = li.sub.id() {
                self.inner.dispatch.since(id, since);
            }
            li.read(pass);
            return;
        }
        let gate = Gate::new(last);
        let (filter, cb) = make(gate.clone());
        let sub = self.subscribe_in(l, filter, false, cb);
        let old = g.insert(key, Listener { sub, gate, pass, reads: 1 });
        drop(g);
        drop(old);
    }

    /// Listens at `w` for what names no value (`Delivery::Due` calls `on_change`), under the
    /// lock `l` of the read it goes with.
    fn track_due(&self, l: &mut Locked, set: &Arc<SetInner>, key: String, w: Watch) {
        let weak = Arc::downgrade(set);
        self.track_in(l, set, key, None, |gate| {
            (Filter::Due(w), Box::new(move |db, d| match d {
                Delivery::Due => gate.fire(&weak, db),
                Delivery::Moved => gate.ended(&weak, db),
                _ => {}
            }))
        });
    }

    /// On a tracking handle: listens for a change of this node's saved peers (`Watch::Local`).
    pub(crate) fn track_saved_peers(&self) -> Result<()> {
        let Some(set) = self.tracking.clone() else { return Ok(()) };
        self.locked(|l| self.track_due(l, &set, "saved_peers".into(), Watch::Local));
        Ok(())
    }

    /// The value `read` reads at `(tid, ak)`, listened to at that address on a tracking handle.
    pub(crate) fn read_value(&self, tid: Tid, ak: &Ak, key: String, read: ReadAt) -> Result<Option<Value>> {
        let Some(set) = self.tracking.clone() else { return self.read_local(|r| read.0(r)) };
        let (ak, limit, actor) = (ak.clone(), self.inner.limit, self.acting);
        self.locked(|l| {
            drop(osis_node::costs::span("read: engine"));
            let v = read.0(&mut Reader { e: l.engine(), limit, actor });
            self.track_in(l, &set, key, digest(&v), |gate| {
                let w = Arc::downgrade(&set);
                (Filter::Aspect(tid, ak, read), value_callback(gate, w))
            });
            v
        })
    }

    /// The answer of `read`, listened to at `at` on a tracking handle: an event there reads it
    /// again and compares with the last read.
    pub(crate) fn read_answer<A: std::fmt::Debug>(&self, key: impl FnOnce() -> String, at: Filter, read: impl Fn(&mut Reader<'_>) -> A + Send + Sync + 'static) -> A {
        let Some(set) = self.tracking.clone() else { return self.read_local(|r| read(r)) };
        let (limit, actor) = (self.inner.limit, self.acting);
        self.locked(|l| {
            drop(osis_node::costs::span("read: engine"));
            let a = read(&mut Reader { e: l.engine(), limit, actor });
            let last = Some(answer_digest(&a));
            let w = Arc::downgrade(&set);
            self.track_in(l, &set, key(), last, move |gate| {
                (at, answer_callback(gate, w, move |r| answer_digest(&read(r)), limit, actor))
            });
            a
        })
    }

    /// On a tracking handle: hears the commits at `a` before the page is read; with `only`, that
    /// one commit's (`commit(id)`: a quote moves with its message alone).
    pub(crate) fn track_commits(&self, a: &Address, only: Option<CommitId>) -> Result<()> {
        let Some(set) = self.tracking.clone() else { return Ok(()) };
        let key = match only {
            Some(c) => format!("{a:?} {c}"),
            None => format!("{a:?}"),
        };
        let mine = move |id: CommitId| only.is_none_or(|c| c == id);
        if let Source::Node(r) = self.source_address(a)? {
            return self.track_remote(key, |gate| {
                let w = Arc::downgrade(&set);
                self.node_on_commits(&r, a.clone(), Box::new(move |db, e| match e {
                    crate::CommitEvent::Ended(_) => gate.ended(&w, db),
                    crate::CommitEvent::Commit { id, .. } if !mine(id) => {}
                    _ => gate.fire(&w, db),
                }))
            });
        }
        let a = a.clone();
        self.locked(|l| {
            // the group's own writes say nothing of a member joining: what it holds is its answer too
            if let Address::Writes(crate::commits::Scope::Group(g)) = &a {
                self.track_due(l, &set, format!("holds {g}"), Watch::Groups(*g));
            }
            self.track_in(l, &set, key, None, |gate| {
                let w = Arc::downgrade(&set);
                (Filter::Commits(a), Box::new(move |db, d| {
                    match d {
                        Delivery::Commit { id, .. } if mine(id) => gate.fire(&w, db),
                        Delivery::Moved => gate.ended(&w, db),
                        _ => {}
                    }
                }))
            });
        });
        Ok(())
    }

    /// On a tracking handle: the status read next is listened to.
    pub(crate) fn track_status(&self) -> Result<()> {
        let Some(set) = self.tracking.clone() else { return Ok(()) };
        if !self.has_store() {
            return self.track_remote("status".into(), |gate| {
                let w = Arc::downgrade(&set);
                self.node_on_status_change(Box::new(move |db, r| gate.called_fire(&w, db, r.is_err())))
            });
        }
        self.locked(|l| {
            self.track_in(l, &set, "status".into(), None, |gate| {
                let w = Arc::downgrade(&set);
                (Filter::Status, Box::new(move |db, d| {
                    match d {
                        Delivery::Status(_) => gate.fire(&w, db),
                        Delivery::Moved => gate.ended(&w, db),
                        _ => {}
                    }
                }))
            });
        });
        Ok(())
    }

    /// A read at a connected node: subscribes first (its listener, once), then the caller reads;
    /// a write in between fires one extra time. The node's own Notify compares values.
    fn track_remote(&self, key: String, sub: impl FnOnce(Arc<Gate>) -> Result<Subscription>) -> Result<()> {
        let Some(set) = self.tracking.clone() else { return Ok(()) };
        let pass = set.pass.load(Ordering::Acquire);
        let mut g = lock(&set.listeners);
        if let Some(li) = g.get_mut(&key).filter(|li| !li.gate.gone.load(Ordering::Acquire)) {
            li.gate.armed.store(true, Ordering::Release);
            li.read(pass);
            return Ok(());
        }
        drop(g);
        let gate = Gate::new(None);
        let s = sub(gate.clone())?;
        let old = lock(&set.listeners).insert(key, Listener { sub: s, gate, pass, reads: 1 });
        drop(old);
        Ok(())
    }

    /// A value read at a connected node: listened to through the node's aspect subscription.
    pub(crate) fn track_remote_value(&self, r: &Arc<crate::port::client::Connection>, tid: Tid, ak: &Ak, path: &osis_schema::Path, key: String) -> Result<()> {
        let Some(set) = self.tracking.clone() else { return Ok(()) };
        self.track_remote(key, |gate| {
            let w = Arc::downgrade(&set);
            self.node_on_change(r, tid, ak.clone(), path.clone(), Box::new(move |db, c| gate.change(&w, db, c.value.is_err(), c.origin == Origin::Initial)))
        })
    }

    /// A read of a thing's aspects at a connected node: heard through its thing subscription.
    pub(crate) fn track_remote_thing(&self, r: &Arc<crate::port::client::Connection>, tid: Tid, key: String) -> Result<()> {
        let Some(set) = self.tracking.clone() else { return Ok(()) };
        self.track_remote(key, |gate| {
            let w = Arc::downgrade(&set);
            self.node_on_thing_change(r, tid, Box::new(move |db, c| gate.change(&w, db, c.value.is_err(), c.origin == Origin::Initial)))
        })
    }

    /// Grants read at a connected node: heard through its grants subscription.
    pub(crate) fn track_remote_grants(&self, r: &Arc<crate::port::client::Connection>, tid: Tid, key: String) -> Result<()> {
        let Some(set) = self.tracking.clone() else { return Ok(()) };
        self.track_remote(key, |gate| {
            let w = Arc::downgrade(&set);
            self.node_on_grants_change(r, tid, Box::new(move |db, g| gate.called_fire(&w, db, g.is_err())))
        })
    }
}

impl Gate {
    /// A remote callback with no origin: its first call is the initial one; an error ends it.
    fn called_fire(&self, set: &Weak<SetInner>, db: &Osis, err: bool) {
        if err {
            self.ended(set, db);
        } else if self.called.swap(true, Ordering::AcqRel) {
            self.fire(set, db);
        }
    }
}

/// A listener on a value: told when the value read differs from the last read.
fn value_callback(gate: Arc<Gate>, set: Weak<SetInner>) -> Callback {
    Box::new(move |db, d| match d {
        Delivery::Aspect { value, origin, .. } => {
            // a large value's blob arrived: a read of its link stays equal, what it reads does not
            let arrived = origin == Origin::Derived(DerivedFrom::Arrived);
            if arrived || value.is_err() || *lock(&gate.last) != digest(&value) {
                gate.fire(&set, db);
            }
        }
        Delivery::Moved => gate.ended(&set, db),
        _ => {}
    })
}

/// A listener on any other read: an event there reads it again, and it is told when the answer
/// differs from the last read.
fn answer_callback(gate: Arc<Gate>, set: Weak<SetInner>, read: impl Fn(&mut Reader<'_>) -> Digest + Send + Sync + 'static, limit: usize, actor: Option<Tid>) -> Callback {
    Box::new(move |db, d| match d {
        Delivery::Due | Delivery::Grants => {
            let now = db.locked(|l| read(&mut Reader { e: l.engine(), limit, actor }));
            if *lock(&gate.last) != Some(now) {
                gate.fire(&set, db);
            }
        }
        Delivery::Moved => gate.ended(&set, db),
        _ => {}
    })
}

/// A digest of an answer no listener delivers: from its `Debug` text, which shows everything a
/// `Grants`, a `GroupsOf`, a stamp or a role holds.
fn answer_digest<A: std::fmt::Debug>(a: &A) -> Digest {
    *blake3::hash(format!("{a:?}").as_bytes()).as_bytes()
}

/// The address `Filter::Due` listens at, in the tracking key.
pub(crate) fn thing_key(what: &str, t: Tid) -> String {
    format!("{what} {t}")
}

/// `Watch` of a read of `t`'s aspects.
pub(crate) fn thing(t: Tid) -> Filter {
    Filter::Due(Watch::Thing(t))
}
