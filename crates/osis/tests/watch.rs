//! Watches, subscriptions, the dispatcher, diagnostics, signals (notes/api.md Watching,
//! Signals, Diagnostics).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;
use common::*;
use osis::{Place, Source, Value};
use std::sync::mpsc::channel;

// notes/api.md Watching: on_change calls once with the current value through the dispatcher,
// then on every committed change (local changes included, after durability).
#[test]
fn on_change_initial_then_local() {
    let db = db(1);
    let k = ak("/t/x");
    let mut w = db.write();
    let t = w.create(db.me(), Place::Unsynced).unwrap();
    w.at(t, k.clone()).set(&Value::Int(1)).unwrap();
    w.commit().unwrap();
    let (tx, rx) = channel();
    let _s = db.at(t, k.clone()).on_change(move |c| tx.send(c).unwrap()).unwrap();
    let c = recv(&rx);
    assert_eq!((c.source, c.value), (Source::Initial, Ok(Some(Value::Int(1)))));
    db.write_with(|w| w.at(t, k.clone()).set(&Value::Int(2))).unwrap();
    let c = recv(&rx);
    assert!(matches!(c.source, Source::Local(i) if i.node == db.node() && i.actor == db.me()));
    assert_eq!(c.value, Ok(Some(Value::Int(2))));
}
