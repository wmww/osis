#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Writing path end to end: identity, creation, ops to commits, local apply, events, restart.

use osis_core::{Ak, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::local_peer::Peer;
use osis_node::{Event, Mutation, Origin};
use osis_schema::core_types as ct;
use std::collections::BTreeMap;

fn ak(s: &str) -> Ak {
    Ak::new(s).unwrap()
}

fn peer(seed: u64) -> Peer {
    Peer::new(seed, WallMs(1_700_000_000_000)).unwrap()
}

// spec/data-model.md §1, §9; spec/permissions.md §4: a new node holds its own thing with
// `/created`, `/node` and `/keys`.
#[test]
fn node_identity_spec_dm_1() {
    let mut p = peer(1);
    let me = p.engine.tid();
    let rec = p.engine.get_typed(&me, &ct::CREATED).unwrap().unwrap();
    assert_eq!(rec.tid(), me);
    assert!(p.engine.get_typed(&me, &ct::NODE).unwrap().is_some());
    let keys = p.engine.get_typed(&me, &ct::KEYS).unwrap().unwrap();
    assert!(keys.key.is_some());
    assert_eq!(p.engine.get(&me, &ak("/tid")).unwrap(), Some(Value::Tid(me)));
    let aspects = p.engine.aspects(&me).unwrap();
    assert!(aspects.contains(&ak("/created")) && aspects.contains(&ak("/node")) && aspects.contains(&ak("/keys")));
    assert_eq!(p.engine.role_on(&me), Some(osis_core::Role::Admin));
}

// spec/crdt.md §4.5, §9; spec/commits.md §1: ops become one commit, applied locally, with an
// event naming the changed aspects (notes/api.md: listeners fire for local writes too).
#[test]
fn write_and_read_spec_crdt_4_5() {
    let mut p = peer(2);
    let me = p.engine.tid();
    p.drain_events();
    let mut m = Mutation::new();
    let t = p.engine.new_thing(&mut m, me);
    let a = ak("/app/title");
    m.set(t, &a, &Value::Str("hello".into())).unwrap();
    let mut map = BTreeMap::new();
    map.insert(Value::Str("x".into()), Value::Int(1));
    m.set(t, &ak("/app/map"), &Value::Map(map)).unwrap();
    let id = p.commit(m).unwrap().unwrap();
    assert_eq!(p.engine.get(&t, &a).unwrap(), Some(Value::Str("hello".into())));
    let ev = p.drain_events();
    let Some(Event::Applied { id: eid, origin, changed, .. }) = ev.iter().find(|e| matches!(e, Event::Applied { .. })) else { panic!("{ev:?}") };
    assert_eq!((*eid, *origin), (id, Origin::Local));
    assert!(changed.contains(&(t, a.clone())) && changed.contains(&(t, ak("/created"))));
    // path op into the map, then a no-op set writes nothing
    let mut m = Mutation::new();
    m.op(t, &ak("/app/map"), PathOp { path: vec![PathSeg::Key(Value::Str("y".into()))], op: Op::Set(Value::Int(2)) }).unwrap();
    p.commit(m).unwrap().unwrap();
    let v = p.engine.get(&t, &ak("/app/map")).unwrap().unwrap();
    let Value::Map(v) = v else { panic!() };
    assert_eq!(v.len(), 2);
    let mut m = Mutation::new();
    m.set(t, &a, &Value::Str("hello".into())).unwrap();
    assert_eq!(p.commit(m).unwrap(), None);
    // remove
    let mut m = Mutation::new();
    m.remove_aspect(t, &a).unwrap();
    p.commit(m).unwrap().unwrap();
    assert_eq!(p.engine.get(&t, &a).unwrap(), None);
}

// spec/crdt.md §2.1, §2.3: node-form counters per (aspect, node) are contiguous from 1.
#[test]
fn counters_contiguous_spec_crdt_2_3() {
    let mut p = peer(3);
    let me = p.engine.tid();
    let mut m = Mutation::new();
    let t = p.engine.new_thing(&mut m, me);
    m.set(t, &ak("/app/n"), &Value::Int(0)).unwrap();
    p.commit(m).unwrap();
    let mut ranges = Vec::new();
    for i in 1..5 {
        let mut m = Mutation::new();
        m.set(t, &ak("/app/n"), &Value::Int(i)).unwrap();
        let id = p.commit(m).unwrap().unwrap();
        let h = p.engine.header(&id).unwrap();
        let a = h.aspects.iter().find(|a| a.ak.as_str() == "/app/n").unwrap();
        ranges.push((a.lo, a.hi));
    }
    assert_eq!(ranges, vec![(2, 3), (3, 4), (4, 5), (5, 6)]);
}

// spec/commits.md §3: commit-form dots carry the commit ID as their source.
#[test]
fn commit_form_spec_commits_3() {
    let mut p = peer(4);
    let me = p.engine.tid();
    let mut m = Mutation::new();
    let t = p.engine.new_thing(&mut m, me);
    m.commit_form();
    m.set(t, &ak("/app/x"), &Value::Int(7)).unwrap();
    let id = p.commit(m).unwrap().unwrap();
    assert_eq!(p.engine.header(&id).unwrap().form, osis_commit::Form::Commit);
    assert_eq!(p.engine.get(&t, &ak("/app/x")).unwrap(), Some(Value::Int(7)));
}

// spec/permissions.md §1: writing a thing needs write on it; an unknown thing is refused.
#[test]
fn authority_checked_before_signing_spec_perm_1() {
    let mut a = peer(5);
    let mut b = peer(6);
    let ta = {
        let me = a.engine.tid();
        let mut m = Mutation::new();
        let t = a.engine.new_thing(&mut m, me);
        m.set(t, &ak("/app/x"), &Value::Int(1)).unwrap();
        a.commit(m).unwrap();
        t
    };
    let mut m = Mutation::new();
    m.set(ta, &ak("/app/x"), &Value::Int(2)).unwrap();
    assert!(matches!(b.commit(m), Err(osis_node::Error::UnknownThing(_))));
    // after receiving the thing, b still holds no role on it
    for id in a.engine.commit_ids() {
        let pk = a.engine.package(&id).unwrap().unwrap();
        b.engine.ingest(&pk.bytes, pk.blobs).unwrap();
    }
    assert_eq!(b.engine.get(&ta, &ak("/app/x")).unwrap(), Some(Value::Int(1)));
    let mut m = Mutation::new();
    m.set(ta, &ak("/app/x"), &Value::Int(2)).unwrap();
    assert!(matches!(b.commit(m), Err(osis_node::Error::Permission { .. })));
}

// notes/local-store.md: everything survives a restart (reload from the store).
#[test]
fn restart_keeps_state() {
    let mut p = peer(7);
    let me = p.engine.tid();
    let mut m = Mutation::new();
    let t = p.engine.new_thing(&mut m, me);
    m.set(t, &ak("/app/x"), &Value::Str("kept".into())).unwrap();
    p.commit(m).unwrap();
    let n = p.engine.commit_ids().len();
    p.restart(70).unwrap();
    assert_eq!(p.engine.tid(), me);
    assert_eq!(p.engine.commit_ids().len(), n);
    assert_eq!(p.engine.get(&t, &ak("/app/x")).unwrap(), Some(Value::Str("kept".into())));
    let mut m = Mutation::new();
    m.set(t, &ak("/app/x"), &Value::Str("again".into())).unwrap();
    let id = p.commit(m).unwrap().unwrap();
    let h = p.engine.header(&id).unwrap();
    assert_eq!(h.aspects[0].lo, 2);
}
