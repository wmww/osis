#![allow(dead_code)]
//! Shared test helpers: deterministic nodes, waiting on channels (never on time).

use osis::internals::Internals as _;
use osis::internals::schema::core_types as ct;
use osis::{Ak, LinkInfo, SignalKey, ValueKey, MemStore, Osis, Result, Store, Subscription, Tid, Time, Write};
use osis::internals::{ManualClock};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

pub const T0: u64 = 1_700_000_000_000;

pub fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(Time(T0)))
}

pub fn cfg(seed: u64, store: MemStore, clock: &Arc<ManualClock>) -> osis::internals::Opening {
    let mut c = osis::internals::Opening::at(Store::Memory(store));
    c.app.internals.seed = Some(seed);
    c.app.internals.clock = Some(clock.clone());
    c
}

/// A fresh node at `T0`.
pub fn db(seed: u64) -> Osis {
    osis::internals::create(cfg(seed, MemStore::new(), &clock())).unwrap()
}

pub fn ak(s: &str) -> Ak {
    Ak::new(s).unwrap()
}

/// Registers on `db` a schema typing each of `aks` `any` (`kept` then names their keys).
pub fn typed_any(db: &Osis, aks: &[&str]) {
    let src: String = aks.iter().map(|a| format!("aspect {a}: any;\n")).collect();
    db.register_schema("kept.osis", &format!("revision 1;\n{src}")).unwrap();
}

/// Kept a day after replaced: what an undo writing back a replaced value needs (spec/crdt.md
/// §4.6).
pub const DAY: osis::History = osis::History::Keep { until: osis::Time(0), after_replaced: std::time::Duration::from_secs(86_400) };

/// A thing's setting keeping each of `entries`' history (spec/commits.md §5 The setting).
pub fn setting(entries: &[(&str, osis::History)]) -> osis::core::RetentionSetting {
    let rules = entries.iter().map(|(a, h)| (ak(a), osis::core::RetentionEntry { history: Some(*h), ..Default::default() })).collect();
    osis::core::RetentionSetting { rules, ..Default::default() }
}

/// `db`, an admin of `t`, writes `t`'s setting keeping `aks` a day after replaced.
pub fn keep_day(db: &Osis, t: Tid, aks: &[&str]) {
    let x = setting(&aks.iter().map(|a| (*a, DAY)).collect::<Vec<_>>());
    db.commit_with(|w| w.at(t, osis::core::RETENTION).set(&x)).unwrap();
}

/// A setting keeping every aspect a day after replaced (its `default`).
pub fn day_default() -> osis::core::RetentionSetting {
    osis::core::RetentionSetting { default: Some(osis::core::RetentionEntry { history: Some(DAY), ..Default::default() }), ..Default::default() }
}

/// In `w`, by an admin of `t`, `t`'s setting keeping every aspect a day: an app creating a thing
/// whose edits it undoes.
pub fn keep_all(w: &mut Write, t: Tid) {
    w.at(t, osis::core::RETENTION).set(&day_default()).unwrap();
}

/// A page of at most `n` commits from `from`, unfiltered.
pub fn page(from: osis::CommitFrom, n: usize) -> osis::CommitQuery {
    osis::CommitQuery { from, limit: Some(n), ..Default::default() }
}

/// Every commit listed in `scope`, newest first (up to a page).
pub fn listed(db: &Osis, scope: osis::Scope) -> Vec<osis::Commit> {
    db.writes(&scope, &osis::CommitQuery::default()).unwrap().commits
}

/// `c`'s part on `k` of `t`, untyped; panics when it has none listed.
pub fn part(c: &osis::Commit, t: Tid, k: &Ak) -> osis::Part<osis::Value> {
    c.at(t, osis::DynamicAspectKey::untyped(k.clone())).unwrap_or_else(|| panic!("no part on {} in {c:?}", k.as_str()))
}

/// The key of `k` as `db` types it (`typed_any`).
pub fn kept(db: &osis::ReadOnly, k: &Ak) -> osis::DynamicAspectKey {
    db.aspect_key(k.as_str()).unwrap()
}

/// Shorthands for tests whose point is what a write does, not how it is spelled.
pub trait TestWrites {
    /// `write()`, `f`, `commit()`: for a commit whose outcome the test inspects as one `Result`.
    fn commit_with<R>(&self, f: impl FnOnce(&mut Write<'_>) -> Result<R>) -> Result<R>;
    /// A commit of one `at(t, key).set(v)`.
    fn commit_set<K: ValueKey>(&self, t: Tid, key: K, v: &K::T) -> Result<()>;
    /// A commit of one `at(t, key).fire(v)`.
    fn commit_fire<K: SignalKey>(&self, t: Tid, key: K, v: &K::T) -> Result<()>;
    /// `retention^.0`'s `retain`, its other rules as they are.
    fn set_retain_copies_default(&self, t: Tid, retain: bool) -> Result<()>;
    /// The links to `t`.
    fn links_of(&self, t: Tid) -> Result<Vec<LinkInfo>>;
}

impl TestWrites for Osis {
    fn commit_with<R>(&self, f: impl FnOnce(&mut Write<'_>) -> Result<R>) -> Result<R> {
        let mut w = self.write();
        let r = f(&mut w)?;
        w.commit()?;
        Ok(r)
    }
    fn commit_set<K: ValueKey>(&self, t: Tid, key: K, v: &K::T) -> Result<()> {
        self.commit_with(|w| w.at(t, key).set(v))
    }
    fn commit_fire<K: SignalKey>(&self, t: Tid, key: K, v: &K::T) -> Result<()> {
        self.commit_with(|w| w.at(t, key).fire(v))
    }
    fn set_retain_copies_default(&self, t: Tid, retain: bool) -> Result<()> {
        let rules = self.at(t, ct::RETENTION).get()?.unwrap_or_default();
        self.commit_set(t, ct::RETENTION, &ct::RetentionSetting { retain, ..rules })
    }
    fn links_of(&self, t: Tid) -> Result<Vec<LinkInfo>> {
        Ok(self.links()?.into_iter().filter(|l| l.target == t).collect())
    }
}

/// The latest value of an aspect, from `on_change`: the value at registration before this returns,
/// no later change missed. Unsubscribes when dropped.
pub struct Watched<T> {
    state: Arc<(Mutex<Latest<T>>, Condvar)>,
    seen: AtomicU64,
    _sub: Subscription,
}

struct Latest<T> {
    value: Option<Result<Option<T>>>,
    /// Changes after the first value.
    version: u64,
}

pub fn watched<K>(db: &Osis, t: Tid, key: K) -> Result<Watched<K::T>>
where
    K: ValueKey + Clone + Send + 'static,
    K::T: PartialEq + Clone + Send + 'static,
{
    let state = Arc::new((Mutex::new(Latest { value: None, version: 0 }), Condvar::new()));
    let st = state.clone();
    let sub = db.at(t, key).on_change(move |_, c| {
        let mut l = st.0.lock().unwrap();
        // what a repeated value (a reconnect's first value) leaves unchanged counts for nothing
        if c.value.is_err() || l.value.as_ref() != Some(&c.value) {
            if l.value.is_some() {
                l.version += 1;
            }
            l.value = Some(c.value);
            st.1.notify_all();
        }
    })?;
    db.settle();
    let w = Watched { state, seen: AtomicU64::new(0), _sub: sub };
    let (mut l, cv) = (w.state.0.lock().unwrap(), &w.state.1);
    while l.value.is_none() {
        let (g, out) = cv.wait_timeout(l, Duration::from_secs(20)).unwrap();
        l = g;
        assert!(!out.timed_out(), "no first value");
    }
    drop(l);
    Ok(w)
}

impl<T: Clone> Watched<T> {
    /// The latest value (`None`: absent).
    pub fn current(&self) -> Result<Option<T>> {
        self.state.0.lock().unwrap().value.clone().unwrap_or(Ok(None))
    }

    /// Whether the value changed since the last `changed*` call returned; marks it seen.
    pub fn try_changed(&self) -> bool {
        let v = self.state.0.lock().unwrap().version;
        self.seen.swap(v, Ordering::AcqRel) < v
    }

    /// Blocks until the value changes or `d` passes; `true` if it changed.
    pub fn changed_timeout(&self, d: Duration) -> bool {
        let end = std::time::Instant::now() + d;
        let mut l = self.state.0.lock().unwrap();
        loop {
            if l.version > self.seen.load(Ordering::Acquire) {
                self.seen.store(l.version, Ordering::Release);
                return true;
            }
            let left = end.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return false;
            }
            l = self.state.1.wait_timeout(l, left).unwrap().0;
        }
    }
}

/// Waits for the next message; a missing callback fails the test instead of hanging.
pub fn recv<T>(rx: &Receiver<T>) -> T {
    rx.recv_timeout(Duration::from_secs(20)).expect("callback did not run")
}

/// `db`'s account keeps account `who` (a contact, a peer it grants): a strong in its account
/// root's `holds.0`, so `who`'s chain stays once received (spec/commits.md §5 What a held thing
/// needs; a strong to a key actor enters nothing). Nothing when it keeps it already.
pub fn know(db: &Osis, who: Tid) {
    let root = db.account_root();
    if who == db.me() || db.engine(|e| e.references_from(&root).unwrap().iter().any(|r| r.target == who && r.kind == osis::RefKind::Strong && r.ak.as_str() == "holds.0")) {
        return;
    }
    db.commit_with(|w| w.at(root, osis::core::HOLDS).path(osis::p![]).add(&osis::Ref::Strong(osis::Strong(who)))).unwrap();
}

/// Delivers every commit `from` holds to `to` (the engine-level path `LocalPeer` uses), `to`
/// keeping `from`'s account (`know`).
pub fn deliver(from: &Osis, to: &Osis) {
    know(to, from.me());
    let pks = from.engine(|e| {
        let ids = e.commit_ids();
        ids.iter().filter_map(|id| e.package(id).unwrap()).collect::<Vec<_>>()
    });
    for pk in pks {
        to.engine(|e| e.ingest(&pk.bytes, pk.blobs.clone()).unwrap());
    }
}

/// Two nodes of one account on one clock; commits travel by `deliver`.
pub fn paired() -> (Osis, Osis, Arc<ManualClock>) {
    let c = clock();
    let a = osis::internals::create(cfg(1, MemStore::new(), &c)).unwrap();
    let j = osis::internals::pair(cfg(2, MemStore::new(), &c), &a.pair_offer().unwrap()).unwrap();
    let (_, reply) = a.pair_accept(j.request()).unwrap();
    let b = j.finish(&reply).unwrap();
    (a, b, c)
}

/// How long `block_on` waits before it calls a wait hung: a test never hangs.
const HUNG: Duration = Duration::from_secs(120);

/// Runs a future to completion on this thread (no runtime: the API's futures are resolved by
/// the node, notes/api-design.md). Panics if it hangs.
pub fn block_on<F: std::future::Future>(f: F) -> F::Output {
    within(HUNG, f).expect("a wait hung")
}

/// `block_on`, what a caller's timeout does: `None`, and `f` dropped, past `d`.
pub fn within<F: std::future::Future>(d: Duration, f: F) -> Option<F::Output> {
    struct Unpark(std::thread::Thread);
    impl std::task::Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = std::task::Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = std::task::Context::from_waker(&waker);
    let mut f = std::pin::pin!(f);
    let end = std::time::Instant::now() + d;
    loop {
        if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return Some(v);
        }
        if std::time::Instant::now() >= end {
            return None;
        }
        std::thread::park_timeout(Duration::from_millis(50));
    }
}

/// Commits the ops `f` makes in one commit; the commit.
pub fn commit_with(db: &Osis, f: impl FnOnce(&mut osis::Write<'_>) -> osis::Result<()>) -> osis::Commit {
    let mut w = db.write();
    f(&mut w).unwrap();
    w.commit().unwrap().unwrap()
}


