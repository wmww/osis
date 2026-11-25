#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Handle, keys, reads, the `Write` commit, rights, errors (notes/api.md Handle, Keys, Reads,
//! Writes, Errors, Footguns closed).

use osis::internals::CommitRaw as _;
use osis::internals::schema::RawKey as _;
use osis::internals::Internals as _;
use crate::common;
use common::*;
use osis::{Error, MemStore, Osis, Role, Value, p};
use std::collections::{BTreeMap, BTreeSet};

use crate::schemas::example;
use example::{Task, task};

fn task(title: &str) -> Task {
    Task { title: title.into(), done: false, tags: BTreeSet::new(), priority: None, due: None, status: None, weight: osis::internals::schema::osis_base::Float::new(1.0) }
}

// notes/api.md Keys: a schema registered at run time types `Key` reads (reader defaults) and
// validates writes; unknown AKs stay untyped.
// spec: none (API surface, notes/api.md)
#[test]
fn registered_schema_key_spec_api_keys() {
    let db = db(0);
    db.register_schema("example.osis", example::SCHEMA.source()).unwrap();
    assert!(db.register_schema("bad.osis", "schema nonsense").is_err());
    // a schema declaring a core AK is the core schema's business, not an app's
    assert!(db.register_schema("core.osis", "revision 1;\naspect name.0: int;\n").is_err());
    assert_eq!(db.aspect_key("name.0").unwrap().schema().map(|s| s.declares_core()), Some(true));
    // a later registration of an AK types it
    db.register_schema("n2.osis", "revision 5;\naspect note:title.0: int;\n").unwrap();
    assert_eq!(db.aspect_key("note:title.0").unwrap().schema().map(|s| s.revision), Some(5));
    db.register_schema("example.osis", example::SCHEMA.source()).unwrap();
    let title = db.aspect_key("note:title.0").unwrap();
    assert!(title.schema().is_some());
    assert!(db.aspect_key("other:x.0").unwrap().schema().is_none());
    let mut w = db.write();
    let n = w.create_held().unwrap();
    assert!(matches!(w.at(n, title.clone()).set(&Value::Int(1)), Err(Error::Type { .. })));
    w.at(n, title.clone()).set(&s("x")).unwrap();
    // a task without `weight` reads with the declared default
    let mut t = BTreeMap::new();
    t.insert(Value::Int(1), s("a"));
    t.insert(Value::Int(2), Value::Bool(false));
    t.insert(Value::Int(3), Value::Set(osis_base::ValueSet::new()));
    w.at(n, untyped("note:tasks.0")).set(&Value::List(vec![Value::Map(t.into_iter().collect())])).unwrap();
    w.commit().unwrap();
    let tasks = db.aspect_key("note:tasks.0").unwrap();
    let v = db.at(n, tasks).path(p![0, task::WEIGHT]).get::<osis::Value>().unwrap();
    assert_eq!(v, Some(Value::float(1.0)));
}

fn titles(db: &Osis, t: osis::Tid) -> Vec<String> {
    db.at(t, example::TASKS).get().unwrap().unwrap().into_iter().map(|x| x.title).collect()
}

// notes/api.md Writes: whole-value ops and every path op.
// spec: none (API surface, notes/api.md)
#[test]
fn write_ops_spec_api_writes() {
    let db = db(0);
    let mut w = db.write();
    let t = w.create_held().unwrap();
    let (m, st, c) = (ak("t:map.0"), ak("t:set.0"), ak("t:reg.0"));
    w.at(t, osis::DynamicAspectKey::untyped(m.clone())).path(p!["a"]).set(&1i64).unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(m.clone())).path(p!["b"]).set(&2i64).unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(st.clone())).path(p![]).add(&"x".to_string()).unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(st.clone())).path(p![]).add(&"y".to_string()).unwrap();
    w.at(t, example::TASKS).set(&vec![task("a"), task("b"), task("c")]).unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(c.clone())).set(&s("one")).unwrap();
    w.commit().unwrap();
    let mut w = db.write();
    w.at(t, osis::DynamicAspectKey::untyped(m.clone())).path(p!["a"]).remove().unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(m.clone())).path(p!["b"]).set(&5i64).unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(st.clone())).path(p!["x"]).remove().unwrap();
    w.at(t, example::TASKS).path(p![]).splice(0..0, &[task("z")]).unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(c.clone())).overwrite(&s("two")).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(m.clone())).get().unwrap(), Some(Value::Map(osis_base::ValueMap::from([(s("b"), Value::Int(5))]))));
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(st.clone())).get().unwrap(), Some(Value::Set(osis_base::ValueSet::from([s("y")]))));
    assert_eq!(titles(&db, t), ["z", "a", "b", "c"]);
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(c.clone())).get().unwrap(), Some(s("two")));
    let mut w = db.write();
    w.at(t, example::TASKS).path(p![]).splice(0..1, ()).unwrap();
    w.at(t, example::TASKS).path(p![2]).remove().unwrap();
    w.commit().unwrap();
    let mut w = db.write();
    w.at(t, example::TASKS).path(p![]).move_range(0..1, 1).unwrap();
    w.commit().unwrap();
    assert_eq!(titles(&db, t), ["b", "a"]);
    let mut w = db.write();
    w.at(t, osis::DynamicAspectKey::untyped(m.clone())).path(p!["b"]).remove().unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(m.clone())).get().unwrap(), Some(Value::Map(osis_base::ValueMap::new())));
    // counter, max, enum case, text splice through typed keys
    let mut w = db.write();
    w.at(t, example::VIEWS).path(osis::Path::root()).contribute(&2i64).unwrap();
    w.at(t, example::VIEWS).path(osis::Path::root()).contribute(&3i64).unwrap();
    w.at(t, example::BODY).set(&"hello world".to_string()).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, example::VIEWS).get().unwrap(), Some(5));
    let mut w = db.write();
    w.at(t, example::BODY).path(p![]).splice(0..5, "goodbye").unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, example::BODY).get().unwrap().as_deref(), Some("goodbye world"));
    db.commit_set(t, example::TASKS, &vec![task("a")]).unwrap();
    let mut w = db.write();
    w.at(t, example::TASKS).path(p![0, task::PRIORITY]).set(&Value::Enum(1, Some(Box::new(Value::Enum(2, None))))).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, example::TASKS).get().unwrap().unwrap()[0].priority, Some(example::Priority::High));
    // max: observe keeps the largest contribution
    db.register_schema("t.osis", "revision 1;\naspect t:max.0: max<int>;\n").unwrap();
    let mx = db.aspect_key("t:max.0").unwrap();
    let mut w = db.write();
    w.at(t, mx.clone()).path(p![]).contribute(&7i64).unwrap();
    w.at(t, mx.clone()).path(p![]).contribute(&3i64).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, mx).get().unwrap(), Some(Value::Int(7)));
    // remove the aspect; a field cannot be removed by path
    let mut w = db.write();
    w.at(t, osis::DynamicAspectKey::untyped(c.clone())).remove().unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(c)).get().unwrap(), None);
    let mut w = db.write();
    assert!(matches!(w.at(t, example::TASKS).path(p![0, task::DONE]).remove(), Err(Error::Invalid(_))));
    // a set element is atomic
    assert!(matches!(w.at(t, osis::DynamicAspectKey::untyped(st)).path(osis::Path(vec![osis::Step::Elem(s("y"))])).set(&1i64), Err(Error::Invalid(_))));
}

// notes/api.md Writes, Footguns closed: `edit(base, new)` keeps a change made to another field
// after the app read `base`; `set` of the same edited value writes that field back.
// spec: none (API surface, notes/api.md)
#[test]
fn edit_keeps_concurrent_change_set_clobbers_spec_api_footguns() {
    let db = db(0);
    let k = ak("t:form.0");
    let form = |a: &str, b: &str| Value::Map(osis_base::ValueMap::from([(Value::Int(0), s(a)), (Value::Int(1), s(b))]));
    let mut w = db.write();
    let t = w.create_held().unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(k.clone())).set(&form("a", "b")).unwrap();
    w.commit().unwrap();
    let shown = db.at(t, osis::DynamicAspectKey::untyped(k.clone())).get().unwrap().unwrap();
    // meanwhile another writer changes field 1
    let mut w = db.write();
    w.at(t, osis::DynamicAspectKey::untyped(k.clone())).path(p![Value::Int(1)]).set(&s("B")).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(k.clone())).get().unwrap(), Some(form("a", "B")));
    // the user edits field 0 of what they were shown
    let edited = form("A", "b");
    let mut w = db.write();
    w.at(t, osis::DynamicAspectKey::untyped(k.clone())).edit(&shown, &edited).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(k.clone())).get().unwrap(), Some(form("A", "B")));
    // `set` of the edited value clobbers the concurrent change
    let mut w = db.write();
    w.at(t, osis::DynamicAspectKey::untyped(k.clone())).path(p![Value::Int(1)]).set(&s("C")).unwrap();
    w.commit().unwrap();
    db.commit_set(t, osis::DynamicAspectKey::untyped(k.clone()), &edited).unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(k)).get().unwrap(), Some(form("A", "b")));
}

// notes/api.md Reads, Large values: a value above the materialization bound fails TooLarge
// (chunked or not); a path read of a small position of the same aspect works.
// spec/data-model.md §6
#[test]
fn materialization_bound_spec_data_model_6() {
    let c = clock();
    let mut cf = cfg(0, MemStore::new(), &c);
    cf.app.read_limit = 64 * 1024;
    let db = osis::internals::create(cf).unwrap();
    let k = ak("t:doc.0");
    let big = Value::Bytes(vec![7u8; osis::internals::schema::osis_base::format::CHUNK_THRESHOLD + 1000]);
    let mid = Value::Bytes(vec![1u8; 100 * 1024]);
    let mut w = db.write();
    let t = w.create_held().unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(k.clone())).set(&Value::Map(osis_base::ValueMap::from([(Value::Int(0), big), (Value::Int(1), s("small")), (Value::Int(2), mid)]))).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(k.clone())).get(), Err(Error::TooLarge { limit: 64 * 1024 }));
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(k.clone())).path(p![osis::FieldId(1)]).get::<String>().unwrap().as_deref(), Some("small"));
    assert!(matches!(db.at(t, osis::DynamicAspectKey::untyped(k.clone())).path(p![osis::FieldId(0)]).get::<osis::Value>(), Err(Error::TooLarge { .. })));
    assert!(matches!(db.at(t, osis::DynamicAspectKey::untyped(k.clone())).path(p![osis::FieldId(2)]).get::<osis::Value>(), Err(Error::TooLarge { .. })));
}

// notes/api.md Reads, Large values: listing a thing's aspects that would hold an unpaged state
// above the read limit fails TooLarge, as a read of it does. spec/data-model.md §6
#[test]
fn aspects_past_the_bound_are_too_large_spec_data_model_6() {
    let c = clock();
    let mut cf = cfg(0, MemStore::new(), &c);
    cf.app.read_limit = 1000;
    let db = osis::internals::create(cf).unwrap();
    let k = osis::DynamicAspectKey::untyped(ak("t:many.0"));
    let mut w = db.write();
    let t = w.create_held().unwrap();
    w.at(t, k.clone()).set(&Value::Map((0..100).map(|i| (s(&format!("someone{i}@example.org")), Value::Int(i))).collect())).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, k).get(), Err(Error::TooLarge { limit: 1000 }));
    assert_eq!(db.aspects(t), Err(Error::TooLarge { limit: 1000 }));
}

// notes/api.md Errors: an engine error the API names is that error whatever call meets it (one
// conversion, no call site): past a read's bound `TooLarge` with that bound, a revert needing
// unkept content `NotUndoable`, a blob storage failure `Storage`; nothing else is one of these.
// spec: none (API surface, notes/api.md)
#[test]
fn engine_errors_map_to_their_api_error_spec_api_errors() {
    use osis::internals::{blob::Error as Data, engine::Error as E, RawCommitId};
    let raw = RawCommitId([7; 32]);
    assert_eq!(Error::from(E::PastBound { bound: 1000 }), Error::TooLarge { limit: 1000 });
    assert_eq!(Error::from(E::NotKept(raw)), Error::NotUndoable { commit: osis::CommitId::from(raw), reason: osis::NotUndoableReason::NotKept });
    assert!(matches!(Error::from(E::Data(Data::Storage("blob"))), Error::Storage(_)));
    assert!(matches!(Error::from(E::Data(Data::TooLarge("claim set"))), Error::Invalid(_)), "a format cap is no read bound");
}

// notes/decode-bounds.md (a read holds at most its bound), spec/wire.md §12: a whole read of an
// aspect whose state is far above the read limit is refused having loaded about the limit of the
// state, at any size of it, and leaves none of it loaded; a path read into it still works.
#[test]
fn a_whole_read_loads_at_most_its_bound_spec_wire_12() {
    let limit = 256 * 1024;
    let pages_read = |n: i64| -> (u64, u64) {
        let c = clock();
        let store = MemStore::new();
        let k = untyped("t:big.0");
        let db = osis::internals::create(cfg(0, store.clone(), &c)).unwrap();
        let t = db.commit_with(|w| {
            let t = w.create_held()?;
            w.at(t, k.clone()).set(&Value::Map((0..n).map(|i| (Value::Int(i), Value::Int(i))).collect()))?;
            Ok(t)
        })
        .unwrap();
        drop(db);
        // reopened: nothing of the state loaded yet
        let mut cf = cfg(0, store, &c);
        cf.app.read_limit = limit;
        let db = osis::internals::open(cf).unwrap();
        // listing the thing's aspects reads each state to its first present piece
        osis::internals::costs::take();
        assert!(db.aspects(t).unwrap().contains(&ak("t:big.0")));
        let c = osis::internals::costs::take();
        let n_of = |name: &str| c.iter().find(|x| x.0 == name).map_or(0, |x| x.2);
        assert_eq!(n_of("state page load"), 0, "n={n}: the listing loads no page into the state");
        let listed = n_of("paged state: piece held");
        let got = db.at(t, k.clone()).get();
        assert!(got == Err(Error::TooLarge { limit }), "n={n}: {:?}", got.map(|v| v.map(|v| osis::internals::schema::osis_base::cbor::encoded_len(&v))));
        let read = osis::internals::costs::take().into_iter().find(|x| x.0 == "state page load").map_or(0, |x| x.2);
        assert!(db.engine(|e| e.core.states.values().flatten().all(|f| f.approx_bytes() < limit)), "n={n}: the read left none of it loaded");
        assert_eq!(db.at(t, k.clone()).path(p![osis::Step::Key(Value::Int(7))]).get::<Value>().unwrap(), Some(Value::Int(7)));
        (read, listed)
    };
    let (small, big) = (pages_read(2_000), pages_read(8_000));
    assert!(small.0 == big.0 && big.0 <= 8, "pages loaded before the refusal: {small:?} at 2000 keys, {big:?} at 8000");
    assert!(small.1 > 0 && small.1 == big.1 && big.1 < limit as u64 / 2, "the most a listing held (a page): {} B at 2000 keys, {} B at 8000", small.1, big.1);
}

// spec/data-model.md §5 (Depth), §6: a large value near the depth limit
// is written and read back, a link counting as the value it reads as (no levels for a string or
// blob); a large map key that would read too deep is refused, though its link alone would fit.
#[test]
fn depth_counts_a_large_value_as_read_spec_data_model_5() {
    use osis::internals::schema::osis_base::format::{CHUNK_THRESHOLD, MAX_VALUE_DEPTH};
    let nest = |mut v: Value, n: usize| {
        for _ in 0..n {
            v = Value::List(vec![v]);
        }
        v
    };
    let db = db(0);
    let k = untyped("t:deep.0");
    let big = Value::Bytes(vec![7u8; CHUNK_THRESHOLD + 1000]);
    for v in [nest(big.clone(), MAX_VALUE_DEPTH), nest(Value::List(vec![big.clone(), s("x")]), MAX_VALUE_DEPTH - 1)] {
        let t = db.commit_with(|w| {
            let t = w.create_held()?;
            w.at(t, k.clone()).set(&v)?;
            Ok(t)
        })
        .unwrap();
        assert!(db.at(t, k.clone()).get().unwrap() == Some(v), "read back whole");
    }
    // a map key reading 30 deep, at depth 40: 70 levels as read, 44 as stored
    let key = nest(Value::List((0..2000).map(|i| s(&format!("{i:0>100}"))).collect()), 29);
    let deep = nest(Value::Map([(key, Value::Int(1))].into_iter().collect()), 39);
    assert!(deep.deeper_than(MAX_VALUE_DEPTH));
    let mut w = db.write();
    let t = w.create_held().unwrap();
    let set = w.at(t, k.clone()).set(&deep);
    assert!(set.is_err() || w.commit().is_err(), "refused as read");
}

// spec/data-model.md §6: a chunked large value reads back whole within the bound.
#[test]
fn large_value_round_trip_spec_data_model_6() {
    let db = db(0);
    let k = ak("t:blob.0");
    let big = Value::Bytes((0..osis::internals::schema::osis_base::format::CHUNK_THRESHOLD * 2).map(|i| (i % 251) as u8).collect());
    let mut w = db.write();
    let t = w.create_held().unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(k.clone())).set(&big).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(k)).get().unwrap(), Some(big));
}

// spec/data-model.md §6 (unreadable link): a node holding a commit but not the blobs of its link
// reads that position absent, the rest of the value as written, and reports `Unreadable`.
#[test]
fn an_unreadable_link_fails_only_its_position_spec_data_model_6() {
    let (a, b, _) = shared();
    let k = untyped("t:doc.0");
    let big = Value::Bytes(vec![7u8; osis::internals::schema::osis_base::format::CHUNK_THRESHOLD + 1000]);
    let t = a.commit_with(|w| {
        let t = w.create_held()?;
        w.at(t, k.clone()).set(&Value::Map(osis_base::ValueMap::from([(Value::Int(0), big), (Value::Int(1), s("small"))])))?;
        Ok(t)
    })
    .unwrap();
    // the commits alone, none of their blobs
    let pks = a.engine(|e| e.commit_ids().iter().filter_map(|id| e.package(id).unwrap()).collect::<Vec<_>>());
    for pk in pks {
        b.engine(|e| e.ingest(&pk.bytes, Vec::new()).unwrap());
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let _d = b.on_diagnostic(move |_, d| tx.send(d).unwrap()).unwrap();
    assert_eq!(b.at(t, k.clone()).get().unwrap(), Some(Value::Map(osis_base::ValueMap::from([(Value::Int(1), s("small"))]))));
    assert_eq!(b.at(t, k.clone()).path(p![osis::FieldId(1)]).get::<String>().unwrap().as_deref(), Some("small"));
    b.settle();
    assert!(rx.try_iter().any(|d| matches!(d, osis::Diagnostic::Unreadable { thing, .. } if thing == t)), "an unreadable link told");
}

// spec/permissions.md §1, notes/api.md Writes: rights are checked locally before signing:
// a node without write on a thing gets Permission; an unknown thing UnknownThing; nothing is
// committed.
#[test]
fn local_rights_check_spec_permissions_1() {
    let a = db(1);
    let b = db(2);
    let mut w = a.write();
    let t = w.create_held().unwrap();
    w.at(t, untyped("t:x.0")).set(&Value::Int(1)).unwrap();
    w.commit().unwrap();
    // b does not know t yet
    let mut w = b.write();
    w.at(t, untyped("t:x.0")).set(&Value::Int(2)).unwrap();
    assert_eq!(w.commit(), Err(Error::UnknownThing { tid: t }));
    deliver(&a, &b);
    // b knows t by its certificates; with no role it holds none of its content (spec/commits.md
    // §4 Outside the node closure)
    assert!(b.created(t).unwrap().is_some());
    assert_eq!(b.at(t, untyped("t:x.0")).get().unwrap(), None);
    assert_eq!(b.role_on(t).unwrap(), None);
    let before = b.engine(|e| e.commit_ids().len());
    let mut w = b.write();
    w.at(t, untyped("t:x.0")).set(&Value::Int(2)).unwrap();
    assert_eq!(w.commit(), Err(Error::Permission { tid: t, needs: Role::Write }));
    assert_eq!(b.engine(|e| e.commit_ids().len()), before);
    // creating under someone else's actor
    let mut w = b.write();
    w.create_held_with_admin(a.author()).unwrap();
    assert!(matches!(w.commit(), Err(Error::Permission { .. })));
    // signals need write too
    let mut w = b.write();
    w.at(t, untyped("t:sig+~0")).fire(&Value::Int(1)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Permission { .. })));
}

// spec/permissions.md §1 (record edge; names as mint admin), §5; notes/api.md Writes: one commit
// creates A, B minted with admin A and C with admin B; another node applying the commit holds
// all three. A thing minted with admin one the writer may not write is still refused.
#[test]
fn tree_in_one_commit_spec_permissions_1() {
    let a = db(1);
    let b = db(2);
    let mut w = a.write();
    let x = w.create_held().unwrap();
    let y = w.create_held_with_admin(x).unwrap();
    let z = w.create_held_with_admin(y).unwrap();
    for (i, t) in [x, y, z].into_iter().enumerate() {
        w.at(t, untyped("t:x.0")).set(&Value::Int(i as i64)).unwrap();
    }
    w.commit().unwrap().unwrap();
    // b reads x, and so y and z in its unit, and holds it: content of a thing outside the node
    // closure waits (spec/commits.md §4 Outside the node closure)
    deliver(&b, &a);
    a.grant(x, b.author(), Role::Read, Default::default()).unwrap();
    commit_with(&b, |w| w.hold(crate::common::home(&b), x));
    deliver(&a, &b);
    for (i, t) in [x, y, z].into_iter().enumerate() {
        assert_eq!(b.engine(|e| e.roster(&t)).get(&[crate::common::home(&a), x, y][i]).map(|e| e.role), Some(Role::Admin), "its mint admin");
        assert!(b.created(t).unwrap().is_some());
        assert_eq!(b.at(t, untyped("t:x.0")).get().unwrap(), Some(Value::Int(i as i64)));
    }
    let before = b.engine(|e| e.commit_ids().len());
    let mut w = b.write();
    let p = w.create_held_with_admin(x).unwrap();
    w.create_held_with_admin(p).unwrap();
    assert!(matches!(w.commit(), Err(Error::Permission { .. })));
    let mut w = b.write();
    let p = w.create_held().unwrap();
    let q = w.create_held_with_admin(z).unwrap();
    w.create_held_with_admin(p).unwrap();
    w.create_held_with_admin(q).unwrap();
    assert!(matches!(w.commit(), Err(Error::Permission { .. })));
    assert_eq!(b.engine(|e| e.commit_ids().len()), before);
}

// spec/crdt.md §4.7: expiry is a hard bound however late the driver's Tick: from T on, no call
// sees the write, durable or ephemeral, with no tick run
#[test]
fn expired_unseen_before_tick_spec_crdt_4_7() {
    let c = clock();
    let db = osis::internals::create(cfg(0, MemStore::new(), &c)).unwrap();
    let (k, e) = (ak("t:msg.0"), ak("t:typing+.0"));
    let mut w = db.write();
    let t = w.create_held().unwrap();
    w.at(t, untyped("t:kept.0")).set(&s("kept")).unwrap();
    w.commit().unwrap();
    for (key, v) in [(&k, "hi"), (&e, "typing")] {
        let mut w = db.write();
        w.expires(osis::Expiry::In(std::time::Duration::from_secs(60)));
        w.at(t, osis::DynamicAspectKey::untyped(key.clone())).set(&s(v)).unwrap();
        w.commit().unwrap();
    }
    c.advance(59_999);
    assert_eq!((db.at(t, osis::DynamicAspectKey::untyped(k.clone())).get().unwrap(), db.at(t, osis::DynamicAspectKey::untyped(e.clone())).get().unwrap()), (Some(s("hi")), Some(s("typing"))));
    c.advance(1);
    assert_eq!((db.at(t, osis::DynamicAspectKey::untyped(k)).get().unwrap(), db.at(t, osis::DynamicAspectKey::untyped(e)).get().unwrap()), (None, None));
}

// spec/commits.md §6, §5: per-write expiry kills the value at T; purge-by per write; purge
// drops the history and removes the aspect.
#[test]
fn expiry_purge_by_and_purge_spec_commits_5_6() {
    let c = clock();
    let db = osis::internals::create(cfg(0, MemStore::new(), &c)).unwrap();
    let (k, r) = (ak("t:msg.0"), ak("t:keep.0"));
    let mut w = db.write();
    let t = w.create_held().unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(r.clone())).purge_by(osis::PurgeBy::Writer).set(&s("kept")).unwrap();
    w.commit().unwrap();
    let mut w = db.write();
    w.expires(osis::Expiry::In(std::time::Duration::from_secs(60)));
    w.at(t, osis::DynamicAspectKey::untyped(k.clone())).set(&s("hi")).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(k.clone())).get().unwrap(), Some(s("hi")));
    c.advance(61_000);
    db.engine(|e| e.tick()).unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(k.clone())).get().unwrap(), None);
    // expiry in the past is invalid at commit
    let mut w = db.write();
    w.expires(osis::Expiry::At(osis::Time(T0)));
    w.at(t, osis::DynamicAspectKey::untyped(k.clone())).set(&s("late")).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(_))));
    // purge
    let mut w = db.write();
    w.at(t, osis::DynamicAspectKey::untyped(r.clone())).purge(osis::Purge::All).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(r.clone())).get().unwrap(), None);
}

// notes/api.md Writes: `act_as` changes the thing the header's path acts on; the default is `me()`.
// spec/commits.md §1
#[test]
fn act_as_spec_commits_1() {
    let db = db(0);
    let mut w = db.write();
    let t = w.create_held().unwrap();
    w.at(t, untyped("t:y.0")).set(&Value::Int(0)).unwrap();
    let c1 = w.commit().unwrap().unwrap();
    let mut w = db.write();
    w.act_as(t);
    w.at(t, untyped("t:x.0")).set(&Value::Int(1)).unwrap();
    let c2 = w.commit().unwrap().unwrap();
    let actor = |c: osis::internals::RawCommitId| db.engine(|e| e.commit_purge_author(&c).unwrap());
    assert_eq!((actor(c1.stamp.id.raw()), actor(c2.stamp.id.raw())), (db.author(), t));
    // an empty write commits nothing
    assert_eq!(db.write().commit().unwrap(), None);
}

// spec/data-model.md §9: `created.0` is typed by its exclusivity rule (admin or key), not the
// missing-field rule, so a run-time core key (`Osis::key`, the CLI's) reads it.
#[test]
fn created_reads_through_run_time_key_spec_data_model_9() {
    let db = osis::internals::create(osis::internals::Opening::memory()).unwrap();
    let mut w = db.write();
    let t = w.create_held().unwrap();
    w.commit().unwrap();
    let v = db.at(t, db.aspect_key("created.0").unwrap()).get().unwrap().unwrap();
    assert!(matches!(&v, Value::Map(m) if m.get(&Value::Int(0)) == Some(&Value::Weak(crate::common::home(&db)))));
}

// notes/api.md Large values, spec/data-model.md §6: a blob above the bound is read by stream
// (`Read + Seek`) and its length known without materializing it; `set_stream` writes one.
#[test]
fn stream_len_set_stream_spec_data_model_6() {
    use std::io::{Read, Seek, SeekFrom};
    let c = clock();
    let mut cf = cfg(0, MemStore::new(), &c);
    cf.app.read_limit = 64 * 1024;
    let db = osis::internals::create(cf).unwrap();
    let k = ak("t:blob.0");
    let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let mut w = db.write();
    let t = w.create_held().unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(k.clone())).path(osis::p![]).set_stream(&data[..]).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(k.clone())).get(), Err(Error::TooLarge { limit: 64 * 1024 }));
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(k.clone())).path(osis::p![]).stream().unwrap().map(|s| s.len()), Some(300_000));
    let mut st = db.at(t, osis::DynamicAspectKey::untyped(k.clone())).path(osis::p![]).stream().unwrap().unwrap();
    let mut all = Vec::new();
    st.read_to_end(&mut all).unwrap();
    assert!(all == data, "whole payload");
    st.seek(SeekFrom::Start(123_457)).unwrap();
    let mut b = [0u8; 10];
    st.read_exact(&mut b).unwrap();
    assert_eq!(&b[..], &data[123_457..123_467]);
    st.seek(SeekFrom::End(-3)).unwrap();
    let mut rest = Vec::new();
    st.read_to_end(&mut rest).unwrap();
    assert_eq!(rest, data[299_997..]);
    // backwards, and relative to the position
    st.seek(SeekFrom::Start(5)).unwrap();
    st.read_exact(&mut b).unwrap();
    assert_eq!(&b[..], &data[5..15]);
    assert_eq!(st.seek(SeekFrom::Current(200_000)).unwrap(), 200_015);
    st.read_exact(&mut b).unwrap();
    assert_eq!(&b[..], &data[200_015..200_025]);
    assert_eq!(st.stream_position().unwrap(), 200_025);
    assert_eq!(st.seek(SeekFrom::Current(-150_000)).unwrap(), 50_025);
    st.read_exact(&mut b).unwrap();
    assert_eq!(&b[..], &data[50_025..50_035]);
    assert!(st.seek(SeekFrom::Current(-60_000)).is_err());
    assert_eq!(st.seek(SeekFrom::End(10)).unwrap(), 300_000, "past the end clamps to the end");
    // a small value streams too; absent reads None; a non-string fails
    let small = ak("t:small.0");
    db.commit_set(t, osis::DynamicAspectKey::untyped(small.clone()), &s("hello")).unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(small.clone())).path(osis::p![]).stream().unwrap().map(|s| s.len()), Some(5));
    assert_eq!(db.at(t, untyped("t:none.0")).path(osis::p![]).stream().unwrap().map(|s| s.len()), None);
    db.commit_set(t, untyped("t:n.0"), &Value::Int(1)).unwrap();
    assert!(matches!(db.at(t, untyped("t:n.0")).path(osis::p![]).stream(), Err(Error::Invalid(_))));
}

// notes/api.md Handle (close): close() from a callback fails at once (it would wait on the
// dispatcher that runs it); from the app it returns once the node is closed.
// spec: none (API surface, notes/api.md)
#[test]
fn close_spec_api_handle() {
    let db = db(0);
    let (tx, rx) = std::sync::mpsc::channel();
    let k = ak("t:x.0");
    let mut w = db.write();
    let t = w.create_held().unwrap();
    w.commit().unwrap();
    let sub = db.at(t, osis::DynamicAspectKey::untyped(k)).on_change(move |db, _| {
        let _ = tx.send(db.clone().close());
    }).unwrap();
    assert!(matches!(recv(&rx), Err(Error::Invalid(_))));
    drop(sub);
    let weak = db.downgrade();
    assert_eq!(db.close().unwrap(), osis::Close::Closed);
    assert!(weak.upgrade().is_none(), "closed when close() returns");
}

// notes/api.md Handle (close): close() tells the truth about the node. Another handle
// keeps it open: `Close::StillOpen` at once, no error. A callback still running: close waits for it, then the
// node is closed; a callback that kept a clone of its handle: StillOpen.
// spec: none (API surface, notes/api.md)
#[test]
fn close_waits_or_names_holders_spec_api_handle() {
    use std::sync::{Arc, Mutex};
    let db = db(0);
    let other = db.clone();
    assert_eq!(db.close(), Ok(osis::Close::StillOpen { handles: 1 }));
    assert_eq!(other.close().unwrap(), osis::Close::Closed);
    for keep in [false, true] {
        let db = common::db(0);
        let k = ak("t:x.0");
        let mut w = db.write();
        let t = w.create_held().unwrap();
        w.commit().unwrap();
        let (entered, rx) = std::sync::mpsc::channel();
        let (go, wait) = std::sync::mpsc::channel::<()>();
        let wait = Mutex::new(wait);
        let kept: Arc<Mutex<Option<Osis>>> = Arc::default();
        let kept2 = kept.clone();
        db.at(t, osis::DynamicAspectKey::untyped(k.clone())).on_change(move |db, c| {
            if c.origin == osis::Origin::Initial {
                return;
            }
            let _ = entered.send(());
            let _ = wait.lock().unwrap().recv();
            if keep {
                *kept2.lock().unwrap() = Some(db.clone());
            }
        }).unwrap().detach();
        db.commit_set(t, osis::DynamicAspectKey::untyped(k.clone()), &Value::Int(1)).unwrap();
        recv(&rx);
        let weak = db.downgrade();
        let closing = std::thread::spawn(move || db.close());
        go.send(()).unwrap();
        let r = closing.join().unwrap();
        if keep {
            assert_eq!(r, Ok(osis::Close::StillOpen { handles: 1 }));
            assert!(weak.upgrade().is_some());
            let db = kept.lock().unwrap().take().unwrap();
            assert_eq!(db.close().unwrap(), osis::Close::Closed);
        } else {
            assert_eq!(r, Ok(osis::Close::Closed));
        }
        assert!(weak.upgrade().is_none(), "closed when close() returns");
    }
}

/// Writes a value nested past the depth limit, a string of `string` bytes and a map of `map`
/// entries; the node errs or accepts, never panics, and keeps working.
fn values_past_limits(string: usize, map: i64) {
    let db = db(1);
    let mut w = db.write();
    let t = w.create_held().unwrap();
    w.commit().unwrap();
    let mut deep = Value::Int(0);
    for _ in 0..600 {
        deep = Value::List(vec![deep]);
    }
    assert!(db.commit_set(t, untyped("t:deep.0"), &deep).is_err(), "nesting past the depth limit accepted");
    let huge = Value::Str("x".repeat(string));
    db.commit_set(t, untyped("t:huge.0"), &huge).unwrap();
    assert_eq!(db.at(t, untyped("t:huge.0")).get().unwrap(), Some(huge));
    let big: osis_base::ValueMap = (0..map).map(|i| (Value::Int(i), Value::Int(i))).collect();
    let _ = db.commit_set(t, untyped("t:map.0"), &Value::Map(big));
    // still working
    db.commit_set(t, untyped("t:x.0"), &Value::Int(1)).unwrap();
    assert_eq!(db.at(t, untyped("t:x.0")).get().unwrap(), Some(Value::Int(1)));
}

// spec/data-model.md §5 (Depth: writers refuse deeper values); notes/api.md Errors: values past the limits
// fail with an error, never a panic: deep nesting, a large string (chunked), a large map (paged)
#[test]
fn values_past_limits_error_spec_data_model() {
    values_past_limits(1 << 20, 20_000);
}

// spec/data-model.md §5; notes/api.md Errors: as above at an 8 MiB string and a 200k-entry map
// (over 20 s in debug).
#[test]
#[ignore = "by hand"]
fn values_past_limits_huge_spec_data_model() {
    values_past_limits(8 << 20, 200_000);
}

// spec/commits.md §2 (a compaction snapshot or ephemeral commit never carries it),
// notes/api.md Reads (`created`): a later compaction snapshot does not replace the creating
// commit; a node holding the snapshot without that commit reports none.
#[test]
fn created_not_a_snapshot_spec_commits_2() {
    let (a, b, c) = shared();
    let mut w = a.write();
    // plain: its creation is the write's own commit
    let t = w.create_held_with_admin(crate::common::home(&a)).unwrap();
    w.at(t, untyped("t:x.0")).set(&s("v")).unwrap();
    let done = w.commit().unwrap().unwrap();
    c.advance(60_000);
    let snap = a.engine(|e| e.snapshot(&t, &ak("t:x.0"))).unwrap().unwrap();
    assert_eq!(a.created(t).unwrap().unwrap().id, done.stamp.id);
    let pks = a.engine(|e| e.commit_ids().iter().filter(|id| **id != done.stamp.id.raw()).filter_map(|id| e.package(id).unwrap()).collect::<Vec<_>>());
    for pk in pks {
        b.engine(|e| e.ingest(&pk.bytes, pk.blobs.clone()).unwrap());
    }
    assert!(b.engine(|e| e.header(&done.stamp.id.raw())).is_none());
    let _ = snap;
    assert_eq!(b.created(t).unwrap(), None);
}

// notes/api.md Reads, spec/crdt.md §4.7: `aspects` lists what reads as present: a register whose
// live write was purged reads what that write replaced, and is listed; with that one purged too
// it reads absent, and is not listed.
#[test]
fn aspects_agrees_with_reads_after_a_purge() {
    let db = db(0);
    let k = ak("t:x.0");
    let mut w = db.write();
    let t = w.create_held().unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(k.clone())).set(&Value::Int(1)).unwrap();
    let first = w.commit().unwrap().unwrap().stamp.id;
    let mut w = db.write();
    w.at(t, osis::DynamicAspectKey::untyped(k.clone())).set(&Value::Int(2)).unwrap();
    let last = w.commit().unwrap().unwrap().stamp.id;
    let purge = |c| {
        let mut w = db.write();
        w.at(t, osis::DynamicAspectKey::untyped(k.clone())).purge(osis::Purge::Commit(c)).unwrap();
        w.commit().unwrap();
    };
    purge(last);
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(k.clone())).get().unwrap(), Some(Value::Int(1)));
    assert!(db.aspects(t).unwrap().contains(&k));
    purge(first);
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(k.clone())).get().unwrap(), None);
    assert!(!db.aspects(t).unwrap().contains(&k));
}

// spec: none (client surface: notes/api.md Writes). The empty path is the whole value: each whole-value op there reads as the aspect's
// own, the collection ops take it too
#[test]
fn the_empty_path_is_the_whole_value() {
    let db = db(0);
    let (k, l) = (ak("t:x.0"), ak("t:s.0"));
    // dependent, in the account root's sync unit
    let t = db.commit_with(|w| {
        let t = w.create_held_with_admin(crate::common::home(&db))?;
        w.at(t, osis::DynamicAspectKey::untyped(k.clone())).path(p![]).set(&Value::Int(1))?;
        Ok(t)
    }).unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(k.clone())).get().unwrap(), Some(Value::Int(1)));
    let n = db.engine(|e| e.commit_ids().len());
    commit_with(&db, |w| w.at(t, osis::DynamicAspectKey::untyped(k.clone())).path(p![]).overwrite(&Value::Int(1)));
    assert_eq!(db.engine(|e| e.commit_ids().len()), n + 1, "an overwrite of an equal value writes");
    let mut w = db.write();
    w.at(t, osis::DynamicAspectKey::untyped(k.clone())).path(p![]).set(&Value::Int(1)).unwrap();
    assert_eq!(w.commit().unwrap(), None, "a set of an equal value does not");
    commit_with(&db, |w| w.at(t, osis::DynamicAspectKey::untyped(k.clone())).path(p![]).set_stream(&b"bytes"[..]));
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(k.clone())).get().unwrap(), Some(Value::Bytes(b"bytes".to_vec())));
    commit_with(&db, |w| w.at(t, osis::DynamicAspectKey::untyped(k.clone())).path(p![]).remove());
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(k.clone())).get().unwrap(), None);
    let mut w = db.write();
    w.at(t, osis::DynamicAspectKey::untyped(k.clone())).path(p!["a"]).set(&Value::Int(1)).unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(l.clone())).path(p![]).add(&Value::Int(1)).unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(l.clone())).path(p![]).add(&Value::Int(2)).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(k)).path(p!["a"]).get::<Value>().unwrap(), Some(Value::Int(1)));
    let mut w = db.write();
    w.at(t, osis::DynamicAspectKey::untyped(l.clone())).path(p![Value::Int(1)]).remove().unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(l)).get().unwrap(), Some(Value::Set([Value::Int(2)].into_iter().collect())));
}

// spec: none (client surface: notes/api.md Writes). One splice for a list and for text: replaces a range, an empty range inserts, no items delete
#[test]
fn splice_lists_and_text() {
    let db = db(0);
    let mut w = db.write();
    let t = w.create_held().unwrap();
    w.at(t, example::TASKS).set(&vec![task("a"), task("b"), task("c")]).unwrap();
    w.at(t, example::BODY).set(&"hello world".to_string()).unwrap();
    w.commit().unwrap();
    let titles = || db.at(t, example::TASKS).get().unwrap().unwrap().into_iter().map(|x| x.title).collect::<Vec<_>>();
    commit_with(&db, |w| w.at(t, example::TASKS).path(p![]).splice(1..2, &[task("x"), task("y")]));
    assert_eq!(titles(), ["a", "x", "y", "c"]);
    commit_with(&db, |w| w.at(t, example::TASKS).path(p![]).splice(0..0, &vec![task("z")]));
    assert_eq!(titles(), ["z", "a", "x", "y", "c"]);
    commit_with(&db, |w| w.at(t, example::TASKS).path(p![]).splice(0..2, ()));
    assert_eq!(titles(), ["x", "y", "c"]);
    let mut w = db.write();
    w.at(t, example::TASKS).path(p![]).splice(1..1, ()).unwrap();
    assert_eq!(w.commit().unwrap(), None, "nothing to do writes nothing");
    let mut w = db.write();
    assert!(matches!(w.at(t, example::TASKS).path(p![]).splice(1..1, "text"), Err(Error::Invalid(_))), "a list takes items");
    assert!(matches!(w.at(t, example::TASKS).path(p![]).splice(1..2, ""), Err(Error::Invalid(_))), "even none, as a string");
    assert!(matches!(w.at(t, example::TASKS).path(p![]).splice(1..1, &[1_i64]), Err(Error::Type { .. })), "of its type");
    #[allow(clippy::reversed_empty_ranges)]
    let backward = 2..1;
    assert!(matches!(w.at(t, example::TASKS).path(p![]).splice(backward, ()), Err(Error::Invalid(_))));
    drop(w);
    commit_with(&db, |w| w.at(t, example::BODY).path(p![]).splice(0..5, "goodbye"));
    assert_eq!(db.at(t, example::BODY).get().unwrap().as_deref(), Some("goodbye world"));
}

// spec: none (client surface: notes/api.md Text editing sessions). Positions are addressed one way: a session at a path as at the aspect
#[test]
fn edit_text_by_position() {
    let db = db(0);
    let k = ak("t:m.0");
    let mut w = db.write();
    let t = w.create_held().unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(k.clone())).path(p!["a"]).set(&"one".to_string()).unwrap();
    w.commit().unwrap();
    let ed = db.at(t, osis::DynamicAspectKey::untyped(k.clone())).path(p!["a"]).edit_text().unwrap();
    assert_eq!(ed.text(), "one");
    ed.edit("one", "one!").unwrap();
    ed.commit().unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(k.clone())).path(p!["a"]).get::<String>().unwrap().as_deref(), Some("one!"));
    assert!(matches!(db.at(t, osis::DynamicAspectKey::untyped(k)).path(osis::p![]).edit_text(), Err(Error::Invalid(_))), "the whole aspect is no string");
}

// spec: none (API surface); notes/api.md Rules: what waits can go on any runtime's spawn
#[test]
fn waiting_calls_are_send() {
    fn send<T: Send>(_: T) {}
    fn all(db: Osis, login: osis::NodeLogin, link: osis::ShareLink, id: osis::LinkId, t: osis::Tid, o: osis::SetRoleOpts) {
        send(db.wait_synced(osis::SyncScope::All));
        send(db.redeem(&link, t));
        send(db.set_role(t, t, None, o));
        send(db.revoke_link(id));
        send(db.connect_node(&login));
        send(db.unit_source(t, osis::UnitSource::Local));
        send(Osis::connect(std::slice::from_ref(&login), osis::AppConfig::default()));
        send(Osis::connect_socket(std::path::Path::new("x"), osis::AppConfig::default()));
    }
    let _ = all;
}

// spec: none (API surface); notes/api.md Reads: a key tells an app the shape of its values, recursive types included, with no schema in sight
#[test]
fn value_type_describes_a_key_api_design() {
    use osis::ValueType as V;
    let db = db(0);
    db.register_schema(
        "t.osis",
        "revision 1;
type tree = struct { label 0: string, kids 1: list<tree> };
type mood = enum { calm 0, odd 1 (int) };
type rec = struct { name 0: string, when 1: timestamp, span 2: duration, nick 3: option<string>, mood 4: mood, tags 5: set<string>, sizes 6: map<string, int>, n 7: counter<int>, body 8: markdown, who 9: weak, data 10: blob, ok 11: bool, x 12: float, tree 13: tree };
aspect t:rec.0: rec;
",
    )
    .unwrap();
    let key = db.aspect_key("t:rec.0").unwrap();
    assert_eq!(key.value_type().unwrap().name(), "rec");
    let V::Record(f) = key.value_type().unwrap().get() else { panic!("a record") };
    let by = |n: &str| f.iter().find(|x| x.name == n).unwrap().clone();
    assert!(matches!(by("name").ty.get(), V::String));
    assert!(matches!(by("when").ty.get(), V::Time));
    assert!(matches!(by("span").ty.get(), V::Duration));
    assert!(matches!(by("body").ty.get(), V::Text));
    assert!(matches!(by("who").ty.get(), V::Weak));
    assert!(matches!(by("data").ty.get(), V::Bytes));
    assert!(matches!(by("ok").ty.get(), V::Bool));
    assert!(matches!(by("x").ty.get(), V::Float));
    assert!(matches!(by("n").ty.get(), V::Counter(_)));
    assert!(matches!(by("tags").ty.get(), V::Set(_)));
    assert!(matches!(by("sizes").ty.get(), V::Map(_, _)));
    let nick = by("nick");
    assert_eq!((nick.ty.name().as_str(), nick.default.clone()), ("option<string>", Some(Value::Enum(0, None))));
    assert!(matches!(nick.ty.get(), V::Optional(p) if p.get() == V::String));
    let V::Cases(c) = by("mood").ty.get() else { panic!("cases") };
    assert_eq!((c[0].id, c[0].name.as_str(), c[0].value.is_none()), (0, "calm", true));
    assert!(matches!(c[1].value.as_ref().unwrap().get(), V::Int));
    // a recursive type describes one level per ask
    let V::Record(t) = by("tree").ty.get() else { panic!("a record") };
    let V::List(kids) = t[1].ty.get() else { panic!("a list") };
    assert!(matches!(kids.get(), V::Record(_)));
    // no schema: nothing to say
    assert_eq!(db.aspect_key("t:other.0").unwrap().value_type(), None);
    assert_eq!(untyped("t:rec.0").value_type(), None);
    assert_eq!(key.default_purge_by(), osis::PurgeBy::Admin);
}

// spec: none (API surface); notes/api.md Commits: a commit's and a place's text form names what it was made from, an entry's or a commit's, and anything else is `Invalid`; a time's place names no commit and comes before what was written then; a place past the last time there is names the end, whichever way a page goes
#[test]
fn commit_places_and_text_forms_api_design() {
    use osis::{CommitFrom as F, CommitPos as P, Time};
    let db = db(0);
    let k = db.aspect_key("t:x.0").unwrap();
    let mut w = db.write();
    let t = w.create_held().unwrap();
    w.at(t, k.clone()).set(&Value::Int(1)).unwrap();
    let done = w.commit().unwrap().unwrap();
    assert_eq!(done.stamp.id.to_string().parse::<osis::CommitId>().unwrap(), done.stamp.id);
    let pages = |f: F| db.at(t, k.clone()).writes(&page(f, 10)).unwrap().commits;
    let pos = pages(F::Newest)[0].pos();
    assert_eq!(pos, done.pos());
    assert_eq!(pos.commit(), Some(done.stamp.id));
    assert_eq!(pos.at(), done.stamp.written);
    let (zero, at, end) = (P::time(Time(0)), P::time(done.stamp.written), P::time(Time(u64::MAX)));
    assert!(zero < at && at < pos && pos < end);
    assert_eq!((at.commit(), end.commit()), (None, None));
    // texts round-trip and sort as places do, a short time's too
    let early = P::time(Time(1));
    assert!(early.to_string() < at.to_string() && at.to_string() < pos.to_string(), "{early} {at} {pos}");
    for p in [zero, at, end, pos] {
        assert_eq!(p.to_string().parse::<P>().unwrap(), p);
    }
    let n = |f: F| pages(f).len();
    assert_eq!((n(F::Before(end)), n(F::After(end))), (1, 0));
    assert_eq!((n(F::Before(zero)), n(F::After(zero))), (0, 1));
    assert_eq!(n(F::Before(at)), 0, "stamped at that moment: after its place");
    assert_eq!(pages(F::After(at))[0].pos(), pos);
    assert_eq!((n(F::Before(pos)), n(F::After(pos))), (0, 0), "neither bound counts itself");
    let m = w_ephemeral(&db, t);
    assert_eq!(m.to_string().parse::<osis::CommitId>().unwrap(), m);
    for bad in ["", "abc", "ephemeral:", "ephemeral:00:1", "ephemeral:zz:1"] {
        assert!(matches!(bad.parse::<osis::CommitId>(), Err(Error::Invalid(_))), "{bad}");
    }
    for bad in ["", "1", "x/y", "1/abc"] {
        assert!(matches!(bad.parse::<P>(), Err(Error::Invalid(_))), "{bad}");
    }
}

fn w_ephemeral(db: &Osis, t: osis::Tid) -> osis::CommitId {
    let mut w = db.write();
    w.at(t, db.aspect_key("t:cursor+.0").unwrap()).set(&Value::Int(1)).unwrap();
    w.commit().unwrap().unwrap().stamp.id
}

// spec/data-model.md §3 (standard named types); notes/api.md Keys: a description sees through aliases and generics to what a type is, `timestamp`, `date` and the like by their own words; what a schema cannot declare never reaches it
#[test]
fn value_type_through_aliases_and_generics_api_design() {
    use osis::ValueType as V;
    let db = db(0);
    db.register_schema(
        "t.osis",
        "revision 1;
type stamp = timestamp;
type stamp2 = stamp;
type box<T> = struct { v 0: T };
type maybe = option<int>;
type rec = struct { a 0: stamp2, b 1: box<stamp>, c 2: maybe, d 3: date, e 4: localtime, f 5: map<string, option<duration>>, g 6: list<box<box<date>>> };
aspect t:rec.0: rec;
aspect t:when.0: stamp;
",
    )
    .unwrap();
    assert_eq!(db.aspect_key("t:when.0").unwrap().value_type().unwrap().get(), V::Time);
    assert_eq!(db.aspect_key("t:when.0").unwrap().value_type().unwrap().name(), "stamp");
    let V::Record(f) = db.aspect_key("t:rec.0").unwrap().value_type().unwrap().get() else { panic!("a record") };
    let by = |n: &str| f.iter().find(|x| x.name == n).unwrap().ty.clone();
    assert_eq!(by("a").get(), V::Time);
    let V::Record(b) = by("b").get() else { panic!("a record") };
    assert_eq!(b[0].ty.get(), V::Time, "a parameter is filled in");
    assert!(matches!(by("c").get(), V::Optional(p) if p.get() == V::Int), "an option by another name");
    assert_eq!((by("d").get(), by("e").get()), (V::Date, V::LocalTime));
    let V::Map(k, v) = by("f").get() else { panic!("a map") };
    assert_eq!(k.get(), V::String);
    assert!(matches!(v.get(), V::Optional(p) if p.get() == V::Duration));
    let V::List(g) = by("g").get() else { panic!("a list") };
    let V::Record(o) = g.get() else { panic!("a record") };
    let V::Record(i) = o[0].ty.get() else { panic!("a record") };
    assert_eq!(i[0].ty.get(), V::Date);
    assert_eq!(format!("{:?}", by("a")), "stamp2", "a type's debug form is its name, not its whole schema");
    // types that never reach a shape, or take a standard name, are refused before a key sees them
    for bad in ["type a = a; aspect t:a.0: a;", "type a = b; type b = a; aspect t:a.0: a;", "type a<T> = a<list<T>>; aspect t:a.0: a<int>;", "type c = counter<c>; aspect t:a.0: c;", "type timestamp = string; aspect t:a.0: timestamp;"] {
        assert!(matches!(db.register_schema("bad.osis", &format!("revision 1; {bad}")), Err(Error::Invalid(_))), "{bad}");
    }
}

// spec: none (API surface); notes/api-design.md No leaks: what a public signature shows can be named: a type in a public field or a call's error is exported
#[test]
fn what_public_signatures_show_can_be_named_api_design() {
    let h = osis::History::Keep { until: osis::Time(0), after_replaced: std::time::Duration::ZERO };
    let _: osis::core::RetentionEntry = osis::core::RetentionEntry { history: Some(h), expires: None, refuse_replace: false };
    let _: osis::PathErrorKind = osis::PathError::new(osis::Path::root(), osis::PathErrorKind::Mismatch { expected: "x" }).kind;
    let _: Result<osis::Ak, osis::AkError> = osis::Ak::new("t:x.0");
    let _: Result<osis::Tid, osis::TidParseError> = osis::Tid::parse("nope");
}

// notes/api.md (`Reads`; spec/crypto.md §4 Floors): a grant without history reads back as such; a
// later grant keeps it unless it says `Reads::All` (never by default), and asking `FromNow` of a
// holder that reads what came before is `Invalid`.
#[test]
fn from_now_grant_is_kept_until_a_grant_shows_everything() {
    let db = common::db(41);
    let (g, n) = db.commit_with(|w| Ok((w.create_held()?, w.create_held()?))).unwrap();
    let opts = |reads| osis::GrantOpts { reads, ..Default::default() };
    db.grant(g, n, Role::Read, opts(osis::Reads::FromNow)).unwrap();
    assert!(db.grants(g).unwrap()[&n].from_now, "granted from now");
    db.grant(g, n, Role::Write, Default::default()).unwrap();
    assert!(db.grants(g).unwrap()[&n].from_now, "a raise by default keeps it");
    db.grant(g, n, Role::Write, opts(osis::Reads::FromNow)).unwrap();
    assert!(db.grants(g).unwrap()[&n].from_now, "a grant saying so keeps it");
    db.set_role(g, n, Some(Role::Admin), Default::default()).unwrap();
    assert!(db.grants(g).unwrap()[&n].from_now, "set_role raising keeps it");
    db.grant(g, n, Role::Admin, opts(osis::Reads::All)).unwrap();
    assert!(!db.grants(g).unwrap()[&n].from_now, "Reads::All shows everything");
    db.grant(g, n, Role::Admin, Default::default()).unwrap();
    assert!(!db.grants(g).unwrap()[&n].from_now, "kept: everything");
    assert!(matches!(db.grant(g, n, Role::Admin, opts(osis::Reads::FromNow)), Err(Error::Invalid(_))), "a holder reading what came before");
}

