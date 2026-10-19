//! Watches, subscriptions, the dispatcher, diagnostics, signals, two nodes (notes/api.md
//! Watching, Signals, Diagnostics, Footguns closed).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;
use common::*;
use osis::{Cause, DiagnosticKind, MemStore, Osis, Place, Source, Target, Value};
use std::sync::mpsc::channel;
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

#[allow(clippy::all, dead_code)]
mod notes {
    use osis::schema as osis_schema;
    include!("../../osis-schema/tests/gen/notes.rs");
}

fn thing(db: &Osis) -> osis::Tid {
    let mut w = db.write();
    let t = w.create(db.me(), Place::Unsynced).unwrap();
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
    let _s = db.at(t, k.clone()).on_change(move |c| tx.send(c).unwrap()).unwrap();
    // a write racing the initial call: initial still shows the value at registration
    db.write_with(|w| w.at(t, k.clone()).set(&Value::Int(2))).unwrap();
    let c = recv(&rx);
    assert_eq!((c.source, c.value), (Source::Initial, Ok(Some(Value::Int(1)))));
    let c = recv(&rx);
    assert!(matches!(c.source, Source::Local(i) if i.node == db.node() && i.actor == db.me()));
    assert_eq!(c.value, Ok(Some(Value::Int(2))));
    // the initial call runs on the dispatcher thread like every later one
    let (tx, rx) = channel();
    let _s2 = db.at(t, k).on_change(move |_| tx.send(std::thread::current().name().map(String::from)).unwrap()).unwrap();
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
    let s = db.at(t, k.clone()).on_change(move |c| tx.send(("dropped", c.value)).unwrap()).unwrap();
    db.at(t, k.clone()).on_change(move |c| tx2.send(("kept", c.value)).unwrap()).unwrap().detach();
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
    let db2 = db.clone();
    let b2 = b.clone();
    let _s = db
        .at(t, a.clone())
        .on_change(move |c| {
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
    let _s = db.watch_thing(t, move |c| tx.send((c.ak.as_str().to_string(), c.source == Source::Initial, c.value)).unwrap());
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
    let db = Osis::create(cfg(1, MemStore::new(), &c)).unwrap();
    let k = ak("/t/x");
    let t = thing(&db);
    db.write_with(|w| w.at(t, k.clone()).expires_in(Duration::from_secs(5)).set(&Value::Int(1))).unwrap();
    let (tx, rx) = channel();
    let _s = db.at(t, k).on_change(move |c| tx.send(c).unwrap()).unwrap();
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
    let _s = db.on_diagnostic(move |d| tx.send(d.kind).unwrap());
    let _ = db.engine(|e| e.ingest(&[0xff, 0x00, 0x01], Vec::new()));
    assert_eq!(recv(&rx), DiagnosticKind::BadInput);
}

// notes/api.md Signals, Fixed directions: a sent signal fires matching listeners on the same
// node, the sender's own included; typed through the generated key.
#[test]
fn local_signals() {
    let db = db(1);
    let t = thing(&db);
    let (tx, rx) = channel();
    let _s = db.on_signal(t, notes::TYPING, move |s| tx.send(s).unwrap());
    let other = thing(&db);
    let (tx2, rx2) = channel();
    let _s2 = db.on_signal(other, notes::TYPING, move |s| tx2.send(s).unwrap());
    let v = notes::Typing { who: db.me(), at: 5 };
    db.send_signal(t, &notes::TYPING, &v, Target::All).unwrap();
    let e = recv(&rx);
    assert_eq!((e.value.unwrap(), e.actor, e.node), (v.clone(), db.me(), db.node()));
    // aimed at another node: no local delivery
    db.send_signal(t, &notes::TYPING, &v, Target::Node(other)).unwrap();
    db.settle();
    assert!(rx.try_recv().is_err());
    assert!(rx2.try_recv().is_err());
}

// spec/permissions.md §2, notes/api.md Watching: watch_roster calls once with the roster now.
#[test]
fn watch_roster_initial() {
    let db = db(1);
    let (tx, rx) = channel();
    let _s = db.watch_roster(db.me(), move |r| tx.send(r).unwrap());
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
    let _s = b.at(t, k.clone()).on_change(move |c| tx.send(c).unwrap()).unwrap();
    let w = b.at(t, k.clone()).watch().unwrap();
    assert_eq!(recv(&rx).source, Source::Initial);
    let done = a.write_with(|w| w.at(t, k.clone()).set(&Value::Int(9))).unwrap().unwrap();
    deliver(&a, &b);
    let c = recv(&rx);
    assert!(matches!(c.source, Source::Remote(i) if i.node == a.node() && i.actor == a.me() && i.id == done.commit));
    assert_eq!(c.value, Ok(Some(Value::Int(9))));
    assert!(w.changed_timeout(Duration::from_secs(20)));
    assert_eq!(w.current().unwrap(), Some(Value::Int(9)));
}
