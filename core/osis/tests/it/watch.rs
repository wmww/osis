//! Watches, subscriptions, the dispatcher, diagnostics, two nodes (notes/api.md Watching,
//! Diagnostics, Footguns closed).
//! spec: none (API surface, notes/api.md).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common;
use common::*;
use osis::{Cause, DiagnosticKind, MemStore, Osis, Source, Value};
use std::sync::mpsc::channel;
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

#[allow(clippy::all, dead_code)]
mod notes {
    use osis::schema as osis_schema;
    include!("../../../schema/tests/gen/notes.rs");
}

fn thing(db: &Osis) -> osis::Tid {
    let mut w = db.write();
    let t = w.create(db.me()).unwrap();
    w.commit().unwrap();
    t
}

// notes/api.md Watching: on_change calls once with the value at registration through the
// dispatcher, then on every committed change (local changes included, after durability).
#[test]
fn on_change_initial_then_local() {
    let db = db(1);
    let k = ak("/t/x");
    let t = thing(&db);
    db.write_with(|w| w.at(t, k.clone()).set(&Value::Int(1))).unwrap();
    let (tx, rx) = channel();
    let _s = db.at(t, k.clone()).on_change(move |_, c| tx.send(c).unwrap()).unwrap();
    // a write racing the initial call: initial still shows the value at registration
    db.write_with(|w| w.at(t, k.clone()).set(&Value::Int(2))).unwrap();
    let c = recv(&rx);
    assert_eq!((c.source, c.value), (Source::Initial, Ok(Some(Value::Int(1)))));
    let c = recv(&rx);
    assert!(matches!(c.source, Source::Local(i) if i.node == db.node() && i.actor == db.me()));
    assert_eq!(c.value, Ok(Some(Value::Int(2))));
    // the initial call runs on the dispatcher thread like every later one
    let (tx, rx) = channel();
    let _s2 = db.at(t, k).on_change(move |_, _| tx.send(std::thread::current().name().map(String::from)).unwrap()).unwrap();
    assert_eq!(recv(&rx).as_deref(), Some("osis-dispatch"));
}

// notes/api.md Watching: a watch is taken atomically with the current value; `changed`
// variants wake on the next change; the async one runs on a plain executor (no runtime).
#[test]
fn watch_current_and_changed() {
    let db = db(1);
    let t = thing(&db);
    let w = db.at(t, notes::TITLE).watch().unwrap();
    assert_eq!(w.current().unwrap(), None);
    assert!(!w.try_changed());
    db.write_with(|x| x.at(t, notes::TITLE).set(&"a".to_string())).unwrap();
    assert!(w.changed_timeout(Duration::from_secs(20)));
    assert_eq!(w.current().unwrap().as_deref(), Some("a"));
    let db2 = db.clone();
    let h = std::thread::spawn(move || {
        db2.write_with(|x| x.at(t, notes::TITLE).set(&"b".to_string())).unwrap();
    });
    block_on(w.changed());
    h.join().unwrap();
    db.settle();
    assert_eq!(w.current().unwrap().as_deref(), Some("b"));
    // writing the same value changes nothing: no wake
    db.write_with(|x| x.at(t, notes::TITLE).set(&"b".to_string())).unwrap();
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
    let k = ak("/t/x");
    let t = thing(&db);
    let (tx, rx) = channel();
    let tx2 = tx.clone();
    let s = db.at(t, k.clone()).on_change(move |_, c| tx.send(("dropped", c.value)).unwrap()).unwrap();
    db.at(t, k.clone()).on_change(move |_, c| tx2.send(("kept", c.value)).unwrap()).unwrap().detach();
    db.settle();
    let first: Vec<_> = rx.try_iter().map(|x| x.0).collect();
    assert_eq!(first.len(), 2);
    drop(s);
    db.write_with(|w| w.at(t, k.clone()).set(&Value::Int(1))).unwrap();
    db.settle();
    let after: Vec<_> = rx.try_iter().collect();
    assert_eq!(after, vec![("kept", Ok(Some(Value::Int(1))))]);
}

// notes/api.md Watching, Footguns closed: any API call works inside a callback (no callback
// under a lock); settle inside a callback returns at once.
#[test]
fn api_usable_from_callback() {
    let db = db(1);
    let (a, b) = (ak("/t/a"), ak("/t/b"));
    let t = thing(&db);
    let (tx, rx) = channel();
    let b2 = b.clone();
    let _s = db
        .at(t, a.clone())
        .on_change(move |db2, c| {
            if let Ok(Some(Value::Int(n))) = c.value {
                db2.write_with(|w| w.at(t, b2.clone()).set(&Value::Int(n * 10))).unwrap();
                db2.settle();
                tx.send(db2.get(t, b2.clone()).unwrap()).unwrap();
            }
        })
        .unwrap();
    db.write_with(|w| w.at(t, a.clone()).set(&Value::Int(4))).unwrap();
    assert_eq!(recv(&rx), Some(Value::Int(40)));
}

// notes/api.md Watching: watch_thing reports every aspect, first once per present aspect.
#[test]
fn watch_thing_all_aspects() {
    let db = db(1);
    let t = thing(&db);
    db.write_with(|w| w.at(t, ak("/t/a")).set(&Value::Int(1))).unwrap();
    let (tx, rx) = channel();
    let _s = db.watch_thing(t, move |_, c| tx.send((c.ak.as_str().to_string(), c.source == Source::Initial, c.value)).unwrap());
    db.write_with(|w| w.at(t, ak("/t/b")).set(&Value::Int(2))).unwrap();
    db.settle();
    let all: Vec<_> = rx.try_iter().collect();
    let initial: std::collections::BTreeSet<&str> = all.iter().filter(|r| r.1).map(|r| r.0.as_str()).collect();
    let present = db.aspects(t).unwrap();
    assert_eq!(initial, present.iter().map(|a| a.as_str()).filter(|a| *a != "/t/b").collect());
    assert!(initial.contains(&"/t/a"));
    assert_eq!(all.iter().filter(|r| !r.1).cloned().collect::<Vec<_>>(), vec![("/t/b".to_string(), false, Ok(Some(Value::Int(2))))]);
}

// spec/commits.md §6, notes/api.md Watching: an expiry changes a value without a commit;
// watches see it as Source::Derived.
#[test]
fn derived_change_on_expiry() {
    let c = clock();
    let db = Osis::create(cfg(1, MemStore::new(), &c)).unwrap().0;
    let k = ak("/t/x");
    let t = thing(&db);
    db.write_with(|w| w.at(t, k.clone()).expires_in(Duration::from_secs(5)).set(&Value::Int(1))).unwrap();
    let (tx, rx) = channel();
    let _s = db.at(t, k).on_change(move |_, c| tx.send(c).unwrap()).unwrap();
    recv(&rx);
    c.advance(6_000);
    db.engine(|e| e.tick()).unwrap();
    let ch = recv(&rx);
    assert_eq!((ch.source, ch.value), (Source::Derived(Cause::Expiry), Ok(None)));
}

// notes/api.md Diagnostics: bad input from a peer is a diagnostic, never an error the app
// must handle beyond the ingest call.
#[test]
fn diagnostics_reach_subscribers() {
    let db = db(1);
    let (tx, rx) = channel();
    let _s = db.on_diagnostic(move |_, d| tx.send(d.kind).unwrap());
    let _ = db.engine(|e| e.ingest(&[0xff, 0x00, 0x01], Vec::new()));
    assert_eq!(recv(&rx), DiagnosticKind::BadInput);
}

// spec/permissions.md §2, notes/api.md Watching: watch_roster calls once with the roster now.
#[test]
fn watch_roster_initial() {
    let db = db(1);
    let (tx, rx) = channel();
    let _s = db.watch_roster(db.me(), move |_, r| tx.send(r).unwrap());
    assert_eq!(recv(&rx), db.roster(db.me()));
}

// notes/api.md Watching, Fixed directions: watches fire on remote writes: a commit made on
// node A and delivered to node B (engine-level delivery, as LocalPeer does) fires B's watch
// with Source::Remote naming A.
#[test]
fn two_nodes_remote_watch() {
    let a = db(1);
    let b = db(2);
    let k = ak("/t/x");
    let t = thing(&a);
    deliver(&a, &b);
    let (tx, rx) = channel();
    let _s = b.at(t, k.clone()).on_change(move |_, c| tx.send(c).unwrap()).unwrap();
    let w = b.at(t, k.clone()).watch().unwrap();
    assert_eq!(recv(&rx).source, Source::Initial);
    let done = commit_with(&a, |w| w.at(t, k.clone()).set(&Value::Int(9)));
    deliver(&a, &b);
    let c = recv(&rx);
    assert!(matches!(c.source, Source::Remote(i) if i.node == a.node() && i.actor == a.me() && i.id == done.id));
    assert_eq!(c.value, Ok(Some(Value::Int(9))));
    assert!(w.changed_timeout(Duration::from_secs(20)));
    assert_eq!(w.current().unwrap(), Some(Value::Int(9)));
}

/// Blocks the dispatcher inside a callback until the returned sender fires.
fn block_dispatcher(db: &Osis) -> (osis::Subscription, std::sync::mpsc::Sender<()>) {
    let t = thing(db);
    let k = ak("/t/gate");
    let (go_tx, go_rx) = channel::<()>();
    let (in_tx, in_rx) = channel();
    let go_rx = Mutex::new(go_rx);
    let s = db
        .at(t, k.clone())
        .on_change(move |_, c| {
            if c.source != Source::Initial {
                in_tx.send(()).unwrap();
                go_rx.lock().unwrap().recv().unwrap();
            }
        })
        .unwrap();
    db.settle();
    db.write_with(|w| w.at(t, k.clone()).set(&Value::Int(1))).unwrap();
    recv(&in_rx);
    (s, go_tx)
}

// notes/api.md Watching: a call that folds several queued commits in carries the newest
// one's source, and the later events are not delivered again.
#[test]
fn coalesced_call_carries_newest_source() {
    let db = db(1);
    let k = ak("/t/x");
    let t = thing(&db);
    let (tx, rx) = channel();
    let _s = db.at(t, k.clone()).on_change(move |_, c| tx.send(c).unwrap()).unwrap();
    db.settle();
    assert_eq!(recv(&rx).source, Source::Initial);
    let (_gate, go) = block_dispatcher(&db);
    db.write_with(|w| w.at(t, k.clone()).set(&Value::Int(1))).unwrap();
    let last = commit_with(&db, |w| w.at(t, k.clone()).set(&Value::Int(2)));
    go.send(()).unwrap();
    db.settle();
    let calls: Vec<_> = rx.try_iter().collect();
    assert_eq!(calls.len(), 1);
    assert!(matches!(calls[0].source, Source::Local(i) if i.id == last.id));
    assert_eq!(calls[0].value, Ok(Some(Value::Int(2))));
}

// notes/api.md Watching: an error (TooLarge) is delivered for every change, never coalesced
// away as "unchanged".
#[test]
fn errors_not_coalesced() {
    let c = clock();
    let mut cf = cfg(1, MemStore::new(), &c);
    cf.materialize_limit = 1000;
    let db = Osis::create(cf).unwrap().0;
    let k = ak("/t/big");
    let t = thing(&db);
    let (tx, rx) = channel();
    let _s = db.at(t, k.clone()).on_change(move |_, c| tx.send(c.value).unwrap()).unwrap();
    let w = db.at(t, k.clone()).watch().unwrap();
    for i in 0..2u8 {
        db.write_with(|w| w.at(t, k.clone()).set(&Value::Bytes(vec![i; 2000]))).unwrap();
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
    let k = ak("/t/x");
    let t = thing(&db);
    let (dtx, drx) = channel();
    let _d = db.on_diagnostic(move |_, d| dtx.send(d.kind).unwrap());
    let _p = db.at(t, k.clone()).on_change(|_, c| assert_eq!(c.source, Source::Initial)).unwrap();
    let (tx, rx) = channel();
    let _s = db.at(t, k.clone()).on_change(move |_, c| tx.send(c.value).unwrap()).unwrap();
    db.write_with(|w| w.at(t, k.clone()).set(&Value::Int(1))).unwrap();
    assert_eq!(recv(&drx), DiagnosticKind::Callback);
    db.settle();
    assert_eq!(rx.try_iter().last(), Some(Ok(Some(Value::Int(1)))));
}

// notes/api.md Watching: dropping a Subscription off the dispatcher waits for a call in
// flight; no call runs after drop returns.
#[test]
fn drop_waits_for_call_in_flight() {
    let db = db(1);
    let k = ak("/t/x");
    let t = thing(&db);
    let done = Arc::new(Mutex::new(0));
    let d2 = done.clone();
    let (in_tx, in_rx) = channel();
    let (go_tx, go_rx) = channel::<()>();
    let go_rx = Mutex::new(go_rx);
    let s = db
        .at(t, k.clone())
        .on_change(move |_, c| {
            if c.source != Source::Initial {
                in_tx.send(()).unwrap();
                go_rx.lock().unwrap().recv().unwrap();
                *d2.lock().unwrap() += 1;
            }
        })
        .unwrap();
    db.write_with(|w| w.at(t, k.clone()).set(&Value::Int(1))).unwrap();
    recv(&in_rx);
    let h = std::thread::spawn(move || go_tx.send(()).unwrap());
    drop(s);
    assert_eq!(*done.lock().unwrap(), 1);
    h.join().unwrap();
    db.write_with(|w| w.at(t, k.clone()).set(&Value::Int(2))).unwrap();
    db.settle();
    assert_eq!(*done.lock().unwrap(), 1);
}

// spec/permissions.md §7, notes/api.md Tids and moves: a watch registered under t fires for
// changes of the thing t moved to.
#[test]
fn watch_follows_move() {
    let db = db(1);
    let k = ak("/t/x");
    let t = thing(&db);
    let owner2 = thing(&db);
    let (tx, rx) = channel();
    let _s = db.at(t, k.clone()).on_change(move |_, c| tx.send(c).unwrap()).unwrap();
    assert_eq!(recv(&rx).source, Source::Initial);
    let m = db.move_thing(t, owner2, &[]).unwrap();
    db.write_with(|w| w.at(m, k.clone()).set(&Value::Int(3))).unwrap();
    db.settle();
    let last = rx.try_iter().last().unwrap();
    assert_eq!((last.tid, last.value), (m, Ok(Some(Value::Int(3)))));
}

// notes/api.md Typed reads: a watch and an `on_change` of a typed key read a stored value of
// another type as absent (the untyped value stays readable).
#[test]
fn mistyped_value_watches_absent() {
    let db = db(1);
    let t = thing(&db);
    db.write_with(|w| w.at(t, notes::TITLE).set(&"a".to_string())).unwrap();
    let w = db.at(t, notes::TITLE).watch().unwrap();
    let (tx, rx) = channel();
    let _s = db.at(t, notes::TITLE).on_change(move |_, c| tx.send(c.value).unwrap()).unwrap();
    assert_eq!(recv(&rx), Ok(Some("a".to_string())));
    db.write_with(|x| x.at(t, ak("/note/title")).set(&Value::Int(3))).unwrap();
    assert_eq!(recv(&rx), Ok(None));
    db.settle();
    assert!(w.try_changed());
    assert_eq!(w.current(), Ok(None));
    db.write_with(|x| x.at(t, notes::TITLE).set(&"b".to_string())).unwrap();
    assert_eq!(recv(&rx), Ok(Some("b".to_string())));
}

// notes/api.md Watching: with `Dispatcher::Pump` callbacks run only inside `settle`, on the
// calling thread, in order; the wake callback fires once per batch of due callbacks; inside a
// callback `settle` returns at once, `close` fails, a write's callback runs in the same pump,
// and a subscription dropped there stops.
#[test]
fn pump_dispatcher_runs_callbacks_in_settle() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let wakes = Arc::new(AtomicUsize::new(0));
    let mut c = cfg(1, MemStore::new(), &clock());
    let w2 = wakes.clone();
    c.dispatch = osis::Dispatcher::Pump(Arc::new(move || {
        w2.fetch_add(1, Ordering::SeqCst);
    }));
    let db = Osis::create(c).unwrap().0;
    db.settle();
    let k = ak("/t/x");
    let t = thing(&db);
    db.settle();
    let base = wakes.load(Ordering::SeqCst);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let me = std::thread::current().id();
    let c2 = calls.clone();
    let k2 = k.clone();
    let _s = db
        .at(t, k.clone())
        .on_change(move |db, c| {
            db.settle();
            assert!(db.clone().close().is_err());
            if c.value == Ok(Some(Value::Int(1))) {
                db.write_with(|w| w.at(t, k2.clone()).set(&Value::Int(2))).unwrap();
            }
            c2.lock().unwrap().push((std::thread::current().id(), c.value.unwrap()));
        })
        .unwrap();
    db.write_with(|w| w.at(t, k.clone()).set(&Value::Int(1))).unwrap();
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
        .at(t, k.clone())
        .on_change(move |_, _| {
            *n2.lock().unwrap() += 1;
            drop(slot2.lock().unwrap().take());
        })
        .unwrap();
    *slot.lock().unwrap() = Some(s);
    db.settle();
    db.write_with(|w| w.at(t, k.clone()).set(&Value::Int(3))).unwrap();
    db.settle();
    assert_eq!(*n.lock().unwrap(), 1);
    // another thread's settle pumps too
    let db2 = db.clone();
    db.write_with(|w| w.at(t, k.clone()).set(&Value::Int(4))).unwrap();
    let other = std::thread::spawn(move || {
        db2.settle();
        std::thread::current().id()
    });
    let id = other.join().unwrap();
    assert_eq!(calls.lock().unwrap().last(), Some(&(id, Some(Value::Int(4)))));
}
