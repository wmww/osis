//! Watches, subscriptions, the dispatcher, diagnostics, two nodes (notes/api.md Watching,
//! Diagnostics, Footguns closed).
//! spec: none (API surface, notes/api.md).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common::watched;
use crate::common::TestWrites as _;
use osis::internals::Internals as _;
use crate::common;
use common::*;
use osis::{DerivedFrom, MemStore, Osis, Origin, Value};
use std::sync::mpsc::channel;
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use crate::schemas::example;

fn thing(db: &Osis) -> osis::Tid {
    let mut w = db.write();
    let t = w.create().unwrap();
    w.commit().unwrap();
    t
}

// notes/api.md Watching: on_change calls once with the value at registration through the
// dispatcher, then on every committed change (local changes included, after durability).
#[test]
fn on_change_initial_then_local() {
    let db = db(1);
    let k = ak("t:x.0");
    let t = thing(&db);
    db.commit_set(t, osis::DynamicAspectKey::untyped(k.clone()), &Value::Int(1)).unwrap();
    let (tx, rx) = channel();
    let _s = db.at(t, osis::DynamicAspectKey::untyped(k.clone())).on_change(move |_, c| tx.send(c).unwrap()).unwrap();
    // a write racing the initial call: initial still shows the value at registration
    db.commit_set(t, osis::DynamicAspectKey::untyped(k.clone()), &Value::Int(2)).unwrap();
    let c = recv(&rx);
    assert_eq!((c.origin, c.value), (Origin::Initial, Ok(Some(Value::Int(1)))));
    let c = recv(&rx);
    assert!(matches!(c.origin, Origin::Local(i) if i.actor == db.me() && i.actor == db.me()));
    assert_eq!(c.value, Ok(Some(Value::Int(2))));
    // the initial call runs on the dispatcher thread like every later one
    let (tx, rx) = channel();
    let _s2 = db.at(t, osis::DynamicAspectKey::untyped(k)).on_change(move |_, _| tx.send(std::thread::current().name().map(String::from)).unwrap()).unwrap();
    assert_eq!(recv(&rx).as_deref(), Some("osis-dispatch"));
}

// notes/api.md Watching: `on_change` is taken atomically with the current value and wakes on the
// next change; forwarded to an async channel it runs on a plain executor (no runtime).
#[test]
fn watch_current_and_changed() {
    let db = db(1);
    let t = thing(&db);
    let w = watched(&db, t, example::TITLE).unwrap();
    assert_eq!(w.current().unwrap(), None);
    assert!(!w.try_changed());
    db.commit_set(t, example::TITLE, &"a".to_string()).unwrap();
    assert!(w.changed_timeout(Duration::from_secs(20)));
    assert_eq!(w.current().unwrap().as_deref(), Some("a"));
    // from async code: on_change forwarded to an async channel
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let _a = db.at(t, example::TITLE).on_change(move |_, c| tx.send(c.value.unwrap()).unwrap()).unwrap();
    assert_eq!(block_on(rx.recv()), Some(Some("a".to_string())), "the current value first");
    let db2 = db.clone();
    let h = std::thread::spawn(move || {
        db2.commit_set(t, example::TITLE, &"b".to_string()).unwrap();
    });
    assert_eq!(block_on(rx.recv()), Some(Some("b".to_string())));
    h.join().unwrap();
    assert!(w.changed_timeout(Duration::from_secs(20)));
    db.settle();
    assert_eq!(w.current().unwrap().as_deref(), Some("b"));
    // writing the same value changes nothing: no wake
    db.commit_set(t, example::TITLE, &"b".to_string()).unwrap();
    db.settle();
    assert!(!w.try_changed());
}

struct Park(Mutex<bool>, Condvar);
impl Wake for Park {
    fn wake(self: Arc<Self>) {
        *self.0.lock().unwrap() = true;
        self.1.notify_all();
    }
}

/// A minimal executor: polls, parks on a condvar until woken.
fn block_on<F: std::future::Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let p = Arc::new(Park(Mutex::new(false), Condvar::new()));
    let waker = Waker::from(p.clone());
    let mut cx = Context::from_waker(&waker);
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
        let mut g = p.0.lock().unwrap();
        while !*g {
            g = p.1.wait(g).unwrap();
        }
        *g = false;
    }
}

// notes/api.md Watching: dropping a Subscription unsubscribes; detach keeps it.
#[test]
fn subscription_raii_and_detach() {
    let db = db(1);
    let k = ak("t:x.0");
    let t = thing(&db);
    let (tx, rx) = channel();
    let tx2 = tx.clone();
    let s = db.at(t, osis::DynamicAspectKey::untyped(k.clone())).on_change(move |_, c| tx.send(("dropped", c.value)).unwrap()).unwrap();
    db.at(t, osis::DynamicAspectKey::untyped(k.clone())).on_change(move |_, c| tx2.send(("kept", c.value)).unwrap()).unwrap().detach();
    db.settle();
    let first: Vec<_> = rx.try_iter().map(|x| x.0).collect();
    assert_eq!(first.len(), 2);
    drop(s);
    db.commit_set(t, osis::DynamicAspectKey::untyped(k.clone()), &Value::Int(1)).unwrap();
    db.settle();
    let after: Vec<_> = rx.try_iter().collect();
    assert_eq!(after, vec![("kept", Ok(Some(Value::Int(1))))]);
}

// notes/api.md Watching, Footguns closed: any API call works inside a callback (no callback
// under a lock); settle inside a callback returns at once.
#[test]
fn api_usable_from_callback() {
    let db = db(1);
    let (a, b) = (ak("t:a.0"), ak("t:b.0"));
    let t = thing(&db);
    let (tx, rx) = channel();
    let b2 = b.clone();
    let _s = db
        .at(t, osis::DynamicAspectKey::untyped(a.clone()))
        .on_change(move |db2, c| {
            if let Ok(Some(Value::Int(n))) = c.value {
                db2.commit_set(t, osis::DynamicAspectKey::untyped(b2.clone()), &Value::Int(n * 10)).unwrap();
                db2.settle();
                tx.send(db2.at(t, osis::DynamicAspectKey::untyped(b2.clone())).get().unwrap()).unwrap();
            }
        })
        .unwrap();
    db.commit_set(t, osis::DynamicAspectKey::untyped(a.clone()), &Value::Int(4)).unwrap();
    assert_eq!(recv(&rx), Some(Value::Int(40)));
}

// notes/api.md Watching: watch_thing reports every aspect, first once per present aspect.
#[test]
fn watch_thing_all_aspects() {
    let db = db(1);
    let t = thing(&db);
    db.commit_set(t, osis::DynamicAspectKey::untyped(ak("t:a.0")), &Value::Int(1)).unwrap();
    let (tx, rx) = channel();
    let _s = db.on_thing_change(t, move |_, c| tx.send((c.ak.as_str().to_string(), c.origin == Origin::Initial, c.value)).unwrap()).unwrap();
    db.commit_set(t, osis::DynamicAspectKey::untyped(ak("t:b.0")), &Value::Int(2)).unwrap();
    db.settle();
    let all: Vec<_> = rx.try_iter().collect();
    let initial: std::collections::BTreeSet<&str> = all.iter().filter(|r| r.1).map(|r| r.0.as_str()).collect();
    let present = db.aspects(t).unwrap();
    assert_eq!(initial, present.iter().map(|a| a.as_str()).filter(|a| *a != "t:b.0").collect());
    assert!(initial.contains(&"t:a.0"));
    assert_eq!(all.iter().filter(|r| !r.1).cloned().collect::<Vec<_>>(), vec![("t:b.0".to_string(), false, Ok(Some(Value::Int(2))))]);
}

// spec/commits.md §6, notes/api.md Watching: an expiry changes a value without a commit;
// watches see it as Origin::Derived.
#[test]
fn derived_change_on_expiry() {
    let c = clock();
    let db = osis::internals::create(cfg(1, MemStore::new(), &c)).unwrap();
    let k = ak("t:x.0");
    let t = thing(&db);
    db.commit_set(t, osis::DynamicAspectKey::untyped(ak("t:kept.0")), &Value::Int(0)).unwrap();
    let mut w = db.write();
    w.expires(osis::Expiry::In(Duration::from_secs(5)));
    w.at(t, osis::DynamicAspectKey::untyped(k.clone())).set(&Value::Int(1)).unwrap();
    w.commit().unwrap();
    let (tx, rx) = channel();
    let _s = db.at(t, osis::DynamicAspectKey::untyped(k)).on_change(move |_, c| tx.send(c).unwrap()).unwrap();
    recv(&rx);
    c.advance(6_000);
    db.engine(|e| e.tick()).unwrap();
    let ch = recv(&rx);
    assert_eq!((ch.origin, ch.value), (Origin::Derived(DerivedFrom::Expired), Ok(None)));
}

// notes/api.md Diagnostics: bad input from a peer is a diagnostic, never an error the app
// must handle beyond the ingest call.
#[test]
fn diagnostics_reach_subscribers() {
    let db = db(1);
    let (tx, rx) = channel();
    let _s = db.on_diagnostic(move |_, d| tx.send(d).unwrap()).unwrap();
    let _ = db.engine(|e| e.ingest(&[0xff, 0x00, 0x01], Vec::new()));
    let d = recv(&rx);
    assert!(matches!(&d, osis::Diagnostic::Handled { detail, .. } if detail.starts_with("BadInput")), "{d:?}");
}

// spec/permissions.md §2, notes/api.md Watching: watch_roster calls once with the roster now.
#[test]
fn watch_roster_initial() {
    let db = db(1);
    let (tx, rx) = channel();
    let _s = db.on_grants_change(db.home(), move |_, r| tx.send(r).unwrap()).unwrap();
    assert_eq!(recv(&rx).unwrap(), db.grants(db.home()).unwrap());
}

// notes/api.md Watching, Fixed directions: watches fire on remote writes: a commit made on
// node A and delivered to node B (engine-level delivery, as LocalPeer does) fires B's watch
// with Origin::Remote naming A.
#[test]
fn two_nodes_remote_watch() {
    let a = db(1);
    let b = db(2);
    let k = ak("t:x.0");
    let t = thing(&a);
    deliver(&a, &b);
    let (tx, rx) = channel();
    let _s = b.at(t, osis::DynamicAspectKey::untyped(k.clone())).on_change(move |_, c| tx.send(c).unwrap()).unwrap();
    let w = watched(&b, t, osis::DynamicAspectKey::untyped(k.clone())).unwrap();
    assert_eq!(recv(&rx).origin, Origin::Initial);
    let done = commit_with(&a, |w| w.at(t, osis::DynamicAspectKey::untyped(k.clone())).set(&Value::Int(9)));
    deliver(&a, &b);
    let c = recv(&rx);
    assert!(matches!(c.origin, Origin::Remote(i) if i.actor == a.me() && i.actor == a.me() && i.id == done.stamp.id));
    assert_eq!(c.value, Ok(Some(Value::Int(9))));
    assert!(w.changed_timeout(Duration::from_secs(20)));
    assert_eq!(w.current().unwrap(), Some(Value::Int(9)));
}

/// Blocks the dispatcher inside a callback until the returned sender fires.
fn block_dispatcher(db: &Osis) -> (osis::Subscription, std::sync::mpsc::Sender<()>) {
    let t = thing(db);
    let k = ak("t:gate.0");
    let (go_tx, go_rx) = channel::<()>();
    let (in_tx, in_rx) = channel();
    let go_rx = Mutex::new(go_rx);
    let s = db
        .at(t, osis::DynamicAspectKey::untyped(k.clone()))
        .on_change(move |_, c| {
            if c.origin != Origin::Initial {
                in_tx.send(()).unwrap();
                go_rx.lock().unwrap().recv().unwrap();
            }
        })
        .unwrap();
    db.settle();
    db.commit_set(t, osis::DynamicAspectKey::untyped(k.clone()), &Value::Int(1)).unwrap();
    recv(&in_rx);
    (s, go_tx)
}

// notes/api.md Watching: a call that folds several queued commits in carries the newest
// one's source, and the later events are not delivered again.
#[test]
fn coalesced_call_carries_newest_source() {
    let db = db(1);
    let k = ak("t:x.0");
    let t = thing(&db);
    let (tx, rx) = channel();
    let _s = db.at(t, osis::DynamicAspectKey::untyped(k.clone())).on_change(move |_, c| tx.send(c).unwrap()).unwrap();
    db.settle();
    assert_eq!(recv(&rx).origin, Origin::Initial);
    let (_gate, go) = block_dispatcher(&db);
    db.commit_set(t, osis::DynamicAspectKey::untyped(k.clone()), &Value::Int(1)).unwrap();
    let last = commit_with(&db, |w| w.at(t, osis::DynamicAspectKey::untyped(k.clone())).set(&Value::Int(2)));
    go.send(()).unwrap();
    db.settle();
    let calls: Vec<_> = rx.try_iter().collect();
    assert_eq!(calls.len(), 1);
    assert!(matches!(calls[0].origin, Origin::Local(i) if i.id == last.stamp.id));
    assert_eq!(calls[0].value, Ok(Some(Value::Int(2))));
}

// notes/api.md Watching: an error (TooLarge) is delivered for every change, never coalesced
// away as "unchanged".
#[test]
fn errors_not_coalesced() {
    let c = clock();
    let mut cf = cfg(1, MemStore::new(), &c);
    cf.app.read_limit = 1000;
    let db = osis::internals::create(cf).unwrap();
    let k = ak("t:big.0");
    let t = thing(&db);
    let (tx, rx) = channel();
    let _s = db.at(t, osis::DynamicAspectKey::untyped(k.clone())).on_change(move |_, c| tx.send(c.value).unwrap()).unwrap();
    let w = watched(&db, t, osis::DynamicAspectKey::untyped(k.clone())).unwrap();
    for i in 0..2u8 {
        db.commit_set(t, osis::DynamicAspectKey::untyped(k.clone()), &Value::Bytes(vec![i; 2000])).unwrap();
        db.settle();
    }
    let errs: Vec<_> = rx.try_iter().filter(|v| matches!(v, Err(osis::Error::TooLarge { limit: 1000 }))).collect();
    assert_eq!(errs.len(), 2);
    assert!(w.try_changed());
    assert!(matches!(w.current(), Err(osis::Error::TooLarge { limit: 1000 })));
}

// notes/api.md Watching: a panicking callback becomes a diagnostic; the dispatcher lives on.
#[test]
fn panicking_callback_is_a_diagnostic() {
    let db = db(1);
    let k = ak("t:x.0");
    let t = thing(&db);
    let (dtx, drx) = channel();
    let _d = db.on_diagnostic(move |_, d| dtx.send(d).unwrap()).unwrap();
    let _p = db.at(t, osis::DynamicAspectKey::untyped(k.clone())).on_change(|_, c| assert_eq!(c.origin, Origin::Initial)).unwrap();
    let (tx, rx) = channel();
    let _s = db.at(t, osis::DynamicAspectKey::untyped(k.clone())).on_change(move |_, c| tx.send(c.value).unwrap()).unwrap();
    db.commit_set(t, osis::DynamicAspectKey::untyped(k.clone()), &Value::Int(1)).unwrap();
    assert!(matches!(recv(&drx), osis::Diagnostic::Callback { .. }));
    db.settle();
    assert_eq!(rx.try_iter().last(), Some(Ok(Some(Value::Int(1)))));
}

// notes/api.md Watching: dropping a Subscription off the dispatcher waits for a call in
// flight; no call runs after drop returns.
#[test]
fn drop_waits_for_call_in_flight() {
    let db = db(1);
    let k = ak("t:x.0");
    let t = thing(&db);
    let done = Arc::new(Mutex::new(0));
    let d2 = done.clone();
    let (in_tx, in_rx) = channel();
    let (go_tx, go_rx) = channel::<()>();
    let go_rx = Mutex::new(go_rx);
    let s = db
        .at(t, osis::DynamicAspectKey::untyped(k.clone()))
        .on_change(move |_, c| {
            if c.origin != Origin::Initial {
                in_tx.send(()).unwrap();
                go_rx.lock().unwrap().recv().unwrap();
                *d2.lock().unwrap() += 1;
            }
        })
        .unwrap();
    db.commit_set(t, osis::DynamicAspectKey::untyped(k.clone()), &Value::Int(1)).unwrap();
    recv(&in_rx);
    let h = std::thread::spawn(move || go_tx.send(()).unwrap());
    drop(s);
    assert_eq!(*done.lock().unwrap(), 1);
    h.join().unwrap();
    db.commit_set(t, osis::DynamicAspectKey::untyped(k.clone()), &Value::Int(2)).unwrap();
    db.settle();
    assert_eq!(*done.lock().unwrap(), 1);
}

// notes/api.md Typed reads: a watch and an `on_change` of a typed key read a stored value of
// another type as absent (the untyped value stays readable).
#[test]
fn mistyped_value_watches_absent() {
    let db = db(1);
    let t = thing(&db);
    db.commit_set(t, example::TITLE, &"a".to_string()).unwrap();
    let w = watched(&db, t, example::TITLE).unwrap();
    let (tx, rx) = channel();
    let _s = db.at(t, example::TITLE).on_change(move |_, c| tx.send(c.value).unwrap()).unwrap();
    assert_eq!(recv(&rx), Ok(Some("a".to_string())));
    db.commit_set(t, osis::DynamicAspectKey::untyped(ak("note:title.0")), &Value::Int(3)).unwrap();
    assert_eq!(recv(&rx), Ok(None));
    db.settle();
    assert!(w.try_changed());
    assert_eq!(w.current(), Ok(None));
    db.commit_set(t, example::TITLE, &"b".to_string()).unwrap();
    assert_eq!(recv(&rx), Ok(Some("b".to_string())));
}

// notes/api.md Watching: with `Dispatcher::Pump` callbacks run only inside `settle`, on the
// calling thread, in order; the wake callback fires once per commit of due callbacks, outside the
// node lock; inside a callback `settle` returns at once, `close` fails, a write's callback
// runs in the same pump, and a subscription dropped there stops.
#[test]
fn pump_dispatcher_runs_callbacks_in_settle() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let wakes = Arc::new(AtomicUsize::new(0));
    let mut c = cfg(1, MemStore::new(), &clock());
    let w2 = wakes.clone();
    // the wake runs after the node lock is released: calling the node there is safe
    let weak: Arc<std::sync::OnceLock<osis::WeakOsis>> = Arc::default();
    let weak2 = weak.clone();
    c.app.dispatch = osis::Dispatcher::Pump(Arc::new(move || {
        w2.fetch_add(1, Ordering::SeqCst);
        if let Some(db) = weak2.get().and_then(|w| w.upgrade()) {
            let _ = db.has_content(db.me());
        }
    }));
    let db = osis::internals::create(c).unwrap();
    weak.set(db.downgrade()).unwrap();
    db.settle();
    let k = ak("t:x.0");
    let t = thing(&db);
    db.settle();
    let base = wakes.load(Ordering::SeqCst);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let me = std::thread::current().id();
    let c2 = calls.clone();
    let k2 = k.clone();
    let _s = db
        .at(t, osis::DynamicAspectKey::untyped(k.clone()))
        .on_change(move |db, c| {
            db.settle();
            assert!(db.clone().close().is_err());
            if c.value == Ok(Some(Value::Int(1))) {
                db.commit_set(t, osis::DynamicAspectKey::untyped(k2.clone()), &Value::Int(2)).unwrap();
            }
            c2.lock().unwrap().push((std::thread::current().id(), c.value.unwrap()));
        })
        .unwrap();
    db.commit_set(t, osis::DynamicAspectKey::untyped(k.clone()), &Value::Int(1)).unwrap();
    assert!(calls.lock().unwrap().is_empty(), "nothing runs before settle");
    assert_eq!(wakes.load(Ordering::SeqCst), base + 1, "one wake for the batch");
    db.settle();
    assert_eq!(*calls.lock().unwrap(), vec![(me, None), (me, Some(Value::Int(1))), (me, Some(Value::Int(2)))], "on this thread, in order");
    db.settle();
    assert_eq!(calls.lock().unwrap().len(), 3);
    // a subscription dropped inside a callback stops
    let n = Arc::new(Mutex::new(0));
    let slot: Arc<Mutex<Option<osis::Subscription>>> = Arc::new(Mutex::new(None));
    let (n2, slot2) = (n.clone(), slot.clone());
    let s = db
        .at(t, osis::DynamicAspectKey::untyped(k.clone()))
        .on_change(move |_, _| {
            *n2.lock().unwrap() += 1;
            drop(slot2.lock().unwrap().take());
        })
        .unwrap();
    *slot.lock().unwrap() = Some(s);
    db.settle();
    db.commit_set(t, osis::DynamicAspectKey::untyped(k.clone()), &Value::Int(3)).unwrap();
    db.settle();
    assert_eq!(*n.lock().unwrap(), 1);
    // another thread's settle pumps too
    let db2 = db.clone();
    db.commit_set(t, osis::DynamicAspectKey::untyped(k.clone()), &Value::Int(4)).unwrap();
    let other = std::thread::spawn(move || {
        db2.settle();
        std::thread::current().id()
    });
    let id = other.join().unwrap();
    assert_eq!(calls.lock().unwrap().last(), Some(&(id, Some(Value::Int(4)))));
}

// spec: none (API surface); notes/api.md Diagnostics, issues/parked-diagnostic.md: a commit from a newer format is told apart from what needs no part from an app
#[test]
fn a_parked_commit_has_its_own_diagnostic() {
    use osis::internals::node::{Diagnostic, DiagnosticKind};
    let d = Diagnostic { kind: DiagnosticKind::Parked, tids: Vec::new(), commit: None, peer: None, detail: "x".into() };
    assert!(matches!(osis::Diagnostic::from(d), osis::Diagnostic::Parked { .. }));
}

// Path listeners (notes/listener-design.md, step 5): a path listener is called exactly when the
// value at its path differs after a transaction, from any cause.

fn untyped(k: &str) -> osis::DynamicAspectKey {
    osis::DynamicAspectKey::untyped(ak(k))
}

fn map(kv: &[(&str, i64)]) -> Value {
    Value::Map(kv.iter().map(|(k, v)| (Value::Str((*k).into()), Value::Int(*v))).collect())
}

/// What a path listener heard: each value with its origin.
type Heard = std::sync::mpsc::Receiver<(osis::Result<Option<Value>>, Origin)>;

/// A listener at `path` of `t`'s `k`, and what it heard.
fn at_path(db: &Osis, t: osis::Tid, k: &str, path: osis::Path) -> (osis::Subscription, Heard) {
    let (tx, rx) = channel();
    let s = db.at(t, untyped(k)).path(path).on_change::<Value>(move |_, c| tx.send((c.value, c.origin)).unwrap()).unwrap();
    (s, rx)
}

/// The values heard since the last call.
fn heard(db: &Osis, rx: &Heard) -> Vec<osis::Result<Option<Value>>> {
    db.settle();
    rx.try_iter().map(|x| x.0).collect()
}

// notes/listener-design.md (step 5): writing map entry `a` calls the `a` listener once and not
// the `b` one; removing `a` reads `None`; a `set` of the whole map calls only the entries it
// changed; deleting the thing reads `None`; a write elsewhere in the thing calls nothing.
#[test]
fn path_listener_hears_only_its_entry() {
    let db = db(1);
    let t = thing(&db);
    db.commit_set(t, untyped("t:m.0"), &map(&[("a", 1), ("b", 1), ("c", 1)])).unwrap();
    let (_a, a) = at_path(&db, t, "t:m.0", osis::p!["a"]);
    let (_b, b) = at_path(&db, t, "t:m.0", osis::p!["b"]);
    let (_c, c) = at_path(&db, t, "t:m.0", osis::p!["c"]);
    assert_eq!(heard(&db, &a), vec![Ok(Some(Value::Int(1)))], "the value at registration");
    assert_eq!(heard(&db, &b), vec![Ok(Some(Value::Int(1)))]);
    heard(&db, &c);
    db.commit_with(|w| w.at(t, untyped("t:m.0")).path(osis::p!["a"]).set(&Value::Int(2))).unwrap();
    assert_eq!(heard(&db, &a), vec![Ok(Some(Value::Int(2)))]);
    assert!(heard(&db, &b).is_empty(), "another entry's write");
    db.commit_set(t, untyped("t:other.0"), &Value::Int(5)).unwrap();
    assert!(heard(&db, &a).is_empty(), "another aspect's write");
    db.commit_with(|w| w.at(t, untyped("t:m.0")).path(osis::p!["a"]).remove()).unwrap();
    assert_eq!(heard(&db, &a), vec![Ok(None)]);
    assert!(heard(&db, &b).is_empty());
    // a whole-map set: `b` changes, `c` does not, `a` comes back
    db.commit_set(t, untyped("t:m.0"), &map(&[("a", 3), ("b", 4), ("c", 1)])).unwrap();
    assert_eq!(heard(&db, &a), vec![Ok(Some(Value::Int(3)))]);
    assert_eq!(heard(&db, &b), vec![Ok(Some(Value::Int(4)))]);
    assert!(heard(&db, &c).is_empty(), "an entry the set left equal");
    db.commit_with(|w| w.delete(t)).unwrap();
    assert_eq!(heard(&db, &a), vec![Ok(None)]);
    assert_eq!(heard(&db, &c), vec![Ok(None)]);
}

// notes/listener-design.md (step 5), notes/api.md Typed reads: a value that does not read as the
// listener's type reads `None` (a `Mismatch` diagnostic), as `get` reads it; a path the schema
// does not have fails `Type` at registration.
#[test]
fn path_listener_mismatch_reads_none() {
    let db = db(1);
    let t = thing(&db);
    db.commit_set(t, untyped("t:m.0"), &map(&[("a", 1)])).unwrap();
    let (diag, dx) = channel();
    let _d = db.on_diagnostic(move |_, d| { let _ = diag.send(d); }).unwrap();
    let (tx, rx) = channel();
    let _s = db.at(t, untyped("t:m.0")).path(osis::p!["a"]).on_change::<i64>(move |_, c| tx.send(c.value).unwrap()).unwrap();
    assert_eq!(recv(&rx), Ok(Some(1)));
    db.commit_with(|w| w.at(t, untyped("t:m.0")).path(osis::p!["a"]).set(&Value::Str("x".into()))).unwrap();
    assert_eq!(recv(&rx), Ok(None));
    assert_eq!(db.at(t, untyped("t:m.0")).path(osis::p!["a"]).get::<i64>().unwrap(), None, "as get reads it");
    db.settle();
    assert!(dx.try_iter().any(|d| matches!(d, osis::Diagnostic::Mismatch { .. })));
    // `note:title.0` is a string: no position inside it
    assert!(matches!(db.at(t, example::TITLE).path(osis::Path(vec![osis::Step::Index(0)])).on_change::<Value>(|_, _| {}), Err(osis::Error::Type { .. })));
}

// notes/listener-design.md (step 5): N listeners on N entries and one write: one call, one read
// per listener (`watch: value read`) and none for listeners elsewhere, each reading only its entry: the pages a listener's
// read loads stay flat as the map grows tenfold, where a whole-aspect watch's grow with it.
#[test]
fn path_listeners_one_write_one_call_n_reads() {
    use osis::internals::node::costs;
    let mut c = cfg(1, MemStore::new(), &clock());
    c.app.dispatch = osis::Dispatcher::Pump(Arc::new(|| {}));
    let db = osis::internals::create(c).unwrap();
    let t = thing(&db);
    let pad = "x".repeat(100);
    let big = |n: usize| Value::Map((0..n).map(|i| (Value::Str(format!("k{i}")), Value::Str(format!("{i}{pad}")))).collect());
    db.commit_set(t, untyped("t:m.0"), &big(20)).unwrap();
    let calls = Arc::new(Mutex::new(0usize));
    let subs: Vec<_> = (0..20)
        .map(|i| {
            let calls = calls.clone();
            db.at(t, untyped("t:m.0")).path(osis::p![format!("k{i}").as_str()]).on_change::<Value>(move |_, _| *calls.lock().unwrap() += 1).unwrap()
        })
        .collect();
    // listeners on another aspect of the thing and on the same aspect of another thing: no read
    let t2 = thing(&db);
    db.commit_set(t2, untyped("t:m.0"), &big(20)).unwrap();
    db.commit_set(t, untyped("t:o.0"), &big(20)).unwrap();
    let others: Vec<_> = [(t, "t:o.0"), (t2, "t:m.0")].into_iter().map(|(x, k)| db.at(x, untyped(k)).path(osis::p!["k3"]).on_change::<Value>(|_, _| {}).unwrap()).collect();
    db.settle();
    *calls.lock().unwrap() = 0;
    db.commit_with(|w| w.at(t, untyped("t:m.0")).path(osis::p!["k3"]).set(&Value::Int(0))).unwrap();
    costs::take();
    db.settle();
    let n = |cs: &[(&str, Duration, u64)], name: &str| cs.iter().find(|x| x.0 == name).map_or(0, |x| x.2);
    let cs = costs::take();
    assert_eq!(*calls.lock().unwrap(), 1, "one call");
    assert_eq!(n(&cs, "watch: value read"), 20, "one read per listener: {cs:?}");
    drop((subs, others));
    // the pages a read loads, at n and 10n entries: one path listener, one whole-aspect watch
    let loads = |n_entries: usize, whole: bool| {
        let t = thing(&db);
        db.commit_set(t, untyped("t:m.0"), &big(n_entries)).unwrap();
        let _s = if whole {
            db.at(t, untyped("t:m.0")).on_change(|_, _| {}).unwrap()
        } else {
            db.at(t, untyped("t:m.0")).path(osis::p!["k1"]).on_change::<Value>(|_, _| {}).unwrap()
        };
        db.settle();
        db.commit_with(|w| w.at(t, untyped("t:m.0")).path(osis::p!["k1"]).set(&Value::Int(0))).unwrap();
        costs::take();
        db.settle();
        let cs = costs::take();
        assert_eq!(n(&cs, "watch: value read"), 1);
        n(&cs, "state page load")
    };
    let (small, large) = (loads(500, false), loads(5000, false));
    let (whole_small, whole_large) = (loads(500, true), loads(5000, true));
    // 500 entries fit unpaged; 5000 take about 76 pages
    assert!(whole_large > 10 * whole_small.max(1), "the counter sees a whole read: {whole_small} -> {whole_large}");
    assert!(large <= small + 1, "a path read loads its pages only: {small} -> {large}");
}

// notes/listener-design.md (step 5), spec/permissions.md §5.1: a write turning invalid with no new
// commit calls the listener at its path, `Derived(ValidityChanged)`, and not the one beside it.
#[test]
fn path_listener_hears_a_validity_flip() {
    use osis_sim::world::World;
    let mut w = World::new();
    let host = w.add_host();
    let alice = w.account(1, &[host]);
    let bob = w.account(2, &[host]);
    w.run();
    let card = bob.contact_card().unwrap();
    w.run();
    let b = w.until(alice.import_contact(&card), 1000, 10).unwrap();
    let g = alice
        .commit_with(|x| {
            let g = x.create()?;
            x.group(alice.home()).add(osis::Member::Item(g))?;
            Ok(g)
        })
        .unwrap();
    alice.sync(g, &[]).unwrap();
    alice.grant(g, b, osis::Role::Write, Default::default()).unwrap();
    w.run();
    for r in bob.invite_requests().unwrap_or_default() {
        let _ = bob.accept_invite(r);
    }
    w.run();
    bob.commit_with(|x| x.at(g, untyped("t:m.0")).path(osis::p!["seen"]).set(&Value::Int(1))).unwrap();
    w.run();
    w.set_online(&bob, false);
    w.advance(1000);
    alice.set_role(g, b, None, osis::SetRoleOpts { retain_copy: Some(true) }).unwrap();
    w.run();
    bob.commit_with(|x| x.at(g, untyped("t:m.0")).path(osis::p!["late"]).set(&Value::Int(2))).unwrap();
    let (_l, late) = at_path(&bob, g, "t:m.0", osis::p!["late"]);
    let (_s, seen) = at_path(&bob, g, "t:m.0", osis::p!["seen"]);
    bob.settle();
    assert_eq!(late.try_iter().map(|x| x.0).collect::<Vec<_>>(), vec![Ok(Some(Value::Int(2)))]);
    assert_eq!(seen.try_iter().map(|x| x.0).collect::<Vec<_>>(), vec![Ok(Some(Value::Int(1)))]);
    w.set_online(&bob, true);
    w.advance(60_000);
    w.run();
    bob.settle();
    assert_eq!(late.try_iter().collect::<Vec<_>>(), vec![(Ok(None), Origin::Derived(DerivedFrom::ValidityChanged))]);
    assert!(seen.try_iter().next().is_none(), "the entry beside it");
}

// notes/listener-design.md (step 5), spec/commits.md §5, §6: an expiry and a purge change a value
// with no new write to it: each calls the listener at the path it changed, and not the one beside
// it.
#[test]
fn path_listener_hears_an_expiry_and_a_purge() {
    let c = clock();
    let db = osis::internals::create(cfg(1, MemStore::new(), &c)).unwrap();
    let t = thing(&db);
    let m = || untyped("t:m.0");
    db.commit_with(|w| w.at(t, m()).path(osis::p!["b"]).set(&Value::Int(1))).unwrap();
    let mut w = db.write();
    w.expires(osis::Expiry::In(Duration::from_secs(5)));
    w.at(t, m()).path(osis::p!["a"]).set(&Value::Int(1)).unwrap();
    w.commit().unwrap();
    db.commit_with(|w| w.at(t, m()).path(osis::p!["c"]).set(&Value::Int(1))).unwrap();
    let cid = db.at(t, m()).writes(&osis::CommitQuery { from: osis::CommitFrom::Newest, limit: Some(1), ..Default::default() }).unwrap().commits[0].stamp.id;
    let (_a, a) = at_path(&db, t, "t:m.0", osis::p!["a"]);
    let (_b, b) = at_path(&db, t, "t:m.0", osis::p!["b"]);
    let (_c, cc) = at_path(&db, t, "t:m.0", osis::p!["c"]);
    db.settle();
    for rx in [&a, &b, &cc] {
        assert_eq!(rx.try_iter().map(|x| x.0).collect::<Vec<_>>(), vec![Ok(Some(Value::Int(1)))]);
    }
    c.advance(6_000);
    db.engine(|e| e.tick()).unwrap();
    db.settle();
    assert_eq!(a.try_iter().collect::<Vec<_>>(), vec![(Ok(None), Origin::Derived(DerivedFrom::Expired))]);
    assert!(heard(&db, &b).is_empty() && heard(&db, &cc).is_empty(), "the entries beside it");
    db.commit_with(|w| w.at(t, m()).purge(osis::Purge::Commit(cid))).unwrap();
    assert_eq!(heard(&db, &cc), vec![Ok(None)], "the purged write's entry");
    assert!(heard(&db, &a).is_empty() && heard(&db, &b).is_empty(), "the entries beside it");
}
