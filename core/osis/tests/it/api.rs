//! Handle, keys, reads, the `Write` commit, rights, errors (notes/api.md Handle, Keys, Reads,
//! Writes, Errors, Footguns closed).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis::internals::Exact as _;
use osis::internals::CommitRaw as _;
use osis::internals::schema::RawKey as _;
use crate::common::watched;
use crate::common::TestWrites as _;
use osis::internals::Internals as _;
use crate::common;
use common::*;
use crate::common::CreateIn;
use osis::internals::schema::core_types::Group;
use osis::{Error, MemStore, Osis, Role, Value, p};
use std::collections::{BTreeMap, BTreeSet};

#[allow(clippy::all, dead_code)]
mod example {
    use osis::internals::schema as osis_schema;
    include!("../../../schema/tests/gen/example.rs");
}
use example::{Task, task};

fn s(x: &str) -> Value {
    Value::Str(x.into())
}

fn task(title: &str) -> Task {
    Task { title: title.into(), done: false, tags: BTreeSet::new(), priority: None, due: None, status: None, weight: osis::internals::schema::osis_base::Float::new(1.0) }
}

// notes/api.md Handle and lifecycle: a new node has a node, an account actor and its home
// group; reopening the store gives the same identity.
// spec: none (API surface, notes/api.md)
#[test]
fn create_and_reopen_spec_api_handle() {
    let store = MemStore::new();
    let c = clock();
    let (node, me) = {
        let db = osis::internals::create(cfg(1, store.clone(), &c)).unwrap();
        assert_ne!(db.me(), db.node());
        assert_eq!(db.at(db.me(), osis::internals::core_types::GROUP).get().unwrap(), Some(Group::default()));
        assert_eq!(db.role_on(db.me()).unwrap(), Some(Role::Admin));
        (db.node(), db.me())
    };
    fn send_sync<T: Send + Sync>() {}
    send_sync::<Osis>();
    send_sync::<osis::Subscription>();
    let db = osis::internals::open(cfg(2, store, &c)).unwrap();
    assert_eq!((db.node(), db.me()), (node, me));
    // an empty store is not a node
    assert!(osis::internals::open(cfg(3, MemStore::new(), &c)).is_err());
}

// spec/versioning.md §5, notes/api.md Keys, Typed reads: typed keys from codegen read and
// write typed values; per-path typed reads; a typed read of mistyped data reads as absent with
// a `Mismatch` diagnostic naming the path, while the untyped read works; one bad element of a
// list fails the whole typed read but not a path read of another element.
// spec/versioning.md §5 (mistyped reads absent)
#[test]
fn typed_keys_and_paths_spec_versioning_5() {
    let db = db(1);
    let mut w = db.write();
    let n = w.create_in(db.me(), &[db.me()]).unwrap();
    w.at(n, example::TITLE).set(&"Groceries".to_string()).unwrap();
    w.at(n, example::TASKS).set(&vec![task("milk"), task("eggs")]).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(n, example::TITLE).get().unwrap().as_deref(), Some("Groceries"));
    assert_eq!(db.at(n, example::TASKS).get().unwrap().unwrap()[1].title, "eggs");
    let at = db.at(n, example::TASKS);
    assert_eq!(at.path(p![1, task::TITLE]).get::<String>().unwrap().as_deref(), Some("eggs"));
    assert_eq!(at.path(p![5, task::TITLE]).get::<osis::Value>().unwrap(), None);
    // path op on a typed list element
    let mut w = db.write();
    w.at(n, example::TASKS).path(p![0, task::DONE]).set(&true).unwrap();
    w.commit().unwrap();
    assert!(db.at(n, example::TASKS).get().unwrap().unwrap()[0].done);
    // mistyped data: untyped write of an int under a string AK
    let (tx, diags) = std::sync::mpsc::channel();
    let _d = db.on_diagnostic(move |_, d| {
        if matches!(d, osis::Diagnostic::Mismatch { .. }) {
            tx.send(d).unwrap();
        }
    }).unwrap();
    db.commit_set(n, osis::DynamicAspectKey::untyped(ak("note:title.0")), &Value::Int(3)).unwrap();
    assert_eq!(db.at(n, example::TITLE).get().unwrap(), None, "absent, not an error");
    let d = recv(&diags);
    assert_eq!(d, osis::Diagnostic::Mismatch { thing: n, detail: "note:title.0: type error at (root): expected string".into() });
    assert_eq!(db.at(n, osis::DynamicAspectKey::untyped(ak("note:title.0"))).get().unwrap(), Some(Value::Int(3)));
    // one element of another shape (as a newer version's enum case would be)
    let Value::List(mut l) = osis::internals::schema::RawKey::encode(&example::TASKS, &vec![task("milk"), task("eggs")]) else { panic!() };
    let Some(Value::Map(m)) = l.get_mut(1) else { panic!() };
    m.insert(Value::Int(1), Value::Int(7));
    db.commit_set(n, osis::DynamicAspectKey::untyped(ak("note:tasks.0")), &Value::List(l)).unwrap();
    assert_eq!(db.at(n, example::TASKS).get().unwrap(), None);
    let at = db.at(n, example::TASKS);
    assert_eq!(at.path(p![0, task::TITLE]).get::<String>().unwrap().as_deref(), Some("milk"));
    assert_eq!(at.path(p![1, task::TITLE]).get::<String>().unwrap(), None);
    assert_eq!(at.path(p![1]).get::<osis::Value>().unwrap(), None);
    assert_eq!(at.path(p![0]).get::<Task>().unwrap().map(|t| t.title).as_deref(), Some("milk"));
    // a path the schema does not have is the caller's mistake: an error
    assert!(matches!(at.path(osis::Path(vec![osis::Step::Index(0), osis::Step::Field(99)])).get::<Value>(), Err(Error::Type { .. })));
    // a typed write is validated against the writer's schema
    let mut w = db.write();
    let e = w.at(n, example::TASKS).path(p![0, task::DONE]).set(&s("no")).unwrap_err();
    assert!(matches!(&e, Error::Type { path, .. } if *path == p![0, task::DONE]), "{e}: the path from the aspect's root");
}

// spec/data-model.md §6, spec/versioning.md §5: a link where the type takes none (a key of a
// `map<tid, _>`) is a mismatch like any other: the typed read is absent with a diagnostic and
// fetches nothing (it failed `blob missing`, so one such key broke every typed read of the aspect).
#[test]
fn link_where_the_type_takes_none_reads_absent_spec_dm_6() {
    let db = db(1);
    let mut w = db.write();
    let n = w.create_in(db.me(), &[db.me()]).unwrap();
    w.commit().unwrap();
    let (tx, diags) = std::sync::mpsc::channel();
    let _d = db.on_diagnostic(move |_, d| {
        if matches!(d, osis::Diagnostic::Mismatch { .. }) {
            tx.send(d).unwrap();
        }
    }).unwrap();
    let bogus = Value::link(osis::internals::schema::osis_base::Link { hash: [3; 32], blob: osis::internals::schema::osis_base::BlobId([4; 32]), suite: 1, key: [5; 32] });
    db.commit_set(n, osis::DynamicAspectKey::untyped(ak("note:pinned.0")), &Value::Map([(bogus, Value::Int(1))].into_iter().collect())).unwrap();
    assert_eq!(db.at(n, example::PINNED).get().unwrap(), None, "absent, not an error");
    assert!(matches!(recv(&diags), osis::Diagnostic::Mismatch { thing, .. } if thing == n));
}

// spec/data-model.md §6 (unreadable link): a link where the type takes one whose value cannot be read (one names
// no blob, one a blob under another thing's dedup secret) reads as absent at its own position, with an `Unreadable` diagnostic; the
// rest of the aspect reads, by typed and untyped reads, watches and `on_change` alike (one such
// set element failed every read of the aspect `blob missing`).
#[test]
fn unreadable_link_reads_absent_at_its_position_spec_dm_6() {
    use osis::internals::schema::osis_base::{BlobId, Link};
    let db = db(1);
    let mut w = db.write();
    let n = w.create_in(db.me(), &[db.me()]).unwrap();
    w.commit().unwrap();
    let (tx, diags) = std::sync::mpsc::channel();
    let _d = db.on_diagnostic(move |_, d| {
        if matches!(d, osis::Diagnostic::Unreadable { .. }) {
            tx.send(d).unwrap();
        }
    }).unwrap();
    let watch = watched(&db, n, example::TASKS).unwrap();
    let (ctx, changes) = std::sync::mpsc::channel();
    let _sub = db.at(n, example::TASKS).on_change(move |_, c| ctx.send(c.value).unwrap()).unwrap();
    assert_eq!(recv(&changes), Ok(None), "the initial call");
    // two tasks, the first's tags holding a link that names no blob
    let tasks = vec![task("a"), task("b")];
    db.commit_set(n, example::TASKS, &tasks).unwrap();
    // calls coalesce (a late call reads the latest state): take this one before the next write
    assert_eq!(recv(&changes), Ok(Some(tasks.clone())));
    let Some(Value::List(mut raw)) = db.at(n, osis::DynamicAspectKey::untyped(ak("note:tasks.0"))).get().unwrap() else { panic!() };
    let Value::Map(first) = &mut raw[0] else { panic!() };
    let bogus = Value::link(Link { hash: [3; 32], blob: BlobId([4; 32]), suite: 1, key: [5; 32] });
    // and a held blob of another thing's large value: under that thing's dedup secret
    let mut w = db.write();
    let m = w.create().unwrap();
    w.commit().unwrap();
    db.commit_set(m, osis::DynamicAspectKey::untyped(ak("t:big.0")), &s(&"x".repeat(200 << 10))).unwrap();
    let foreign = db.engine(|e| e.get(&m, &ak("t:big.0"))).unwrap().unwrap();
    assert!(matches!(foreign, Value::Link(_)));
    first.insert(Value::Int(task::TAGS.0 as i64), Value::Set([s("kept"), bogus, foreign].into_iter().collect()));
    db.commit_set(n, osis::DynamicAspectKey::untyped(ak("note:tasks.0")), &Value::List(raw)).unwrap();
    let mut want = tasks.clone();
    want[0].tags = ["kept".to_string()].into();
    assert_eq!(db.at(n, example::TASKS).get().unwrap(), Some(want.clone()), "the rest reads");
    let d = recv(&diags);
    let osis::Diagnostic::Unreadable { thing, detail } = d else { panic!("{d:?}") };
    assert_eq!(thing, n);
    assert!(detail.contains("blob missing") && detail.contains("verification failed"), "{detail}");
    assert_eq!(db.at(n, example::TASKS).path(p![0, task::TAGS]).get::<BTreeSet<String>>().unwrap(), Some(["kept".to_string()].into()));
    assert_eq!(db.at(n, example::TASKS).path(p![1]).get::<Task>().unwrap(), Some(task("b")));
    // on_change: the write with the link; the watch holds it too
    assert_eq!(recv(&changes), Ok(Some(want.clone())));
    assert_eq!(watch.current(), Ok(Some(want)));
    // at the aspect root: the aspect reads absent, not an error
    let k = ak("t:x.0");
    db.commit_set(n, osis::DynamicAspectKey::untyped(k.clone()), &Value::link(Link { hash: [6; 32], blob: BlobId([7; 32]), suite: 1, key: [8; 32] })).unwrap();
    assert_eq!(db.at(n, osis::DynamicAspectKey::untyped(k)).get().unwrap(), None);
}

// spec/data-model.md §6 (unreadable link): a link whose blob is not held yet reads absent, and
// once the blob arrives the aspect's watches and `on_change` get its value without any change
// to the aspect.
#[test]
fn missed_blob_arriving_redelivers_watches_spec_dm_6() {
    let db = db(1);
    let mut w = db.write();
    let n = w.create_in(db.me(), &[db.me()]).unwrap();
    w.commit().unwrap();
    let k = ak("t:big.0");
    let big = s(&"x".repeat(200 << 10));
    db.commit_set(n, osis::DynamicAspectKey::untyped(k.clone()), &big).unwrap();
    let Some(Value::Link(l)) = db.engine(|e| e.get(&n, &k)).unwrap() else { panic!() };
    let bytes = db.engine(|e| e.blob(&l.blob)).unwrap().unwrap();
    db.engine(|e| {
        e.run(|tx| {
            tx.txn.delete_blob(&l.blob);
            Ok(())
        })
    })
    .unwrap();
    let watch = watched(&db, n, osis::DynamicAspectKey::untyped(k.clone())).unwrap();
    assert_eq!(watch.current(), Ok(None), "not held: absent");
    let (tx, changes) = std::sync::mpsc::channel();
    let _sub = db.at(n, osis::DynamicAspectKey::untyped(k.clone())).on_change(move |_, c| tx.send((c.value, c.origin)).unwrap()).unwrap();
    assert_eq!(recv(&changes), (Ok(None), osis::Origin::Initial));
    db.engine(|e| e.put_blobs(vec![(l.blob, bytes)])).unwrap();
    assert_eq!(recv(&changes), (Ok(Some(big.clone())), osis::Origin::Derived(osis::DerivedFrom::Arrived)));
    assert_eq!(watch.current(), Ok(Some(big)));
}

// notes/api.md Keys: a schema registered at run time types `Key` reads (reader defaults) and
// validates writes; unknown AKs stay untyped.
// spec: none (API surface, notes/api.md)
#[test]
fn registered_schema_key_spec_api_keys() {
    let db = db(1);
    db.register_schema("example.osis", example::SCHEMA.source()).unwrap();
    assert!(db.register_schema("bad.osis", "schema nonsense").is_err());
    // a schema declaring a core AK is the core schema's business, not an app's
    assert!(db.register_schema("core.osis", "version 1;\naspect name.0: int;\n").is_err());
    assert_eq!(db.aspect_key("name.0").unwrap().schema().map(|s| s.declares_core()), Some(true));
    // a later registration of an AK types it
    db.register_schema("n2.osis", "version 5;\naspect note:title.0: int;\n").unwrap();
    assert_eq!(db.aspect_key("note:title.0").unwrap().schema().map(|s| s.version), Some(5));
    db.register_schema("example.osis", example::SCHEMA.source()).unwrap();
    let title = db.aspect_key("note:title.0").unwrap();
    assert!(title.schema().is_some());
    assert!(db.aspect_key("other:x.0").unwrap().schema().is_none());
    let mut w = db.write();
    let n = w.create().unwrap();
    assert!(matches!(w.at(n, title.clone()).set(&Value::Int(1)), Err(Error::Type { .. })));
    w.at(n, title.clone()).set(&s("x")).unwrap();
    // a task without `weight` reads with the declared default
    let mut t = BTreeMap::new();
    t.insert(Value::Int(1), s("a"));
    t.insert(Value::Int(2), Value::Bool(false));
    t.insert(Value::Int(3), Value::Set(osis_base::ValueSet::new()));
    w.at(n, osis::DynamicAspectKey::untyped(ak("note:tasks.0"))).set(&Value::List(vec![Value::Map(t.into_iter().collect())])).unwrap();
    w.commit().unwrap();
    let tasks = db.aspect_key("note:tasks.0").unwrap();
    let v = db.at(n, tasks).path(p![0, task::WEIGHT]).get::<osis::Value>().unwrap();
    assert_eq!(v, Some(Value::float(1.0)));
}

// notes/api.md Reads: absent aspects and unknown things read as None, never as errors.
// spec: none (API surface, notes/api.md)
#[test]
fn absent_reads_none_spec_api_reads() {
    let db = db(1);
    let other = db_other_thing();
    assert_eq!(db.at(other, osis::DynamicAspectKey::untyped(ak("a:b.0"))).get().unwrap(), None);
    assert_eq!(db.at(db.me(), osis::DynamicAspectKey::untyped(ak("a:b.0"))).get().unwrap(), None);
    assert!(!db.has_content(other).unwrap());
    assert_eq!(db.role_on(other).unwrap(), None);
}

fn db_other_thing() -> osis::Tid {
    let o = db(9);
    o.me()
}

fn titles(db: &Osis, t: osis::Tid) -> Vec<String> {
    db.at(t, example::TASKS).get().unwrap().unwrap().into_iter().map(|x| x.title).collect()
}

// notes/api.md Writes: whole-value ops and every path op.
// spec: none (API surface, notes/api.md)
#[test]
fn write_ops_spec_api_writes() {
    let db = db(1);
    let mut w = db.write();
    let t = w.create().unwrap();
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
    db.register_schema("t.osis", "version 1;\naspect t:max.0: max<int>;\n").unwrap();
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
    let db = db(1);
    let k = ak("t:form.0");
    let form = |a: &str, b: &str| Value::Map(osis_base::ValueMap::from([(Value::Int(0), s(a)), (Value::Int(1), s(b))]));
    let mut w = db.write();
    let t = w.create().unwrap();
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
    let mut cf = cfg(1, MemStore::new(), &c);
    cf.app.read_limit = 64 * 1024;
    let db = osis::internals::create(cf).unwrap();
    let k = ak("t:doc.0");
    let big = Value::Bytes(vec![7u8; osis::internals::schema::osis_base::format::CHUNK_THRESHOLD + 1000]);
    let mid = Value::Bytes(vec![1u8; 100 * 1024]);
    let mut w = db.write();
    let t = w.create().unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(k.clone())).set(&Value::Map(osis_base::ValueMap::from([(Value::Int(0), big), (Value::Int(1), s("small")), (Value::Int(2), mid)]))).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(k.clone())).get(), Err(Error::TooLarge { limit: 64 * 1024 }));
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(k.clone())).path(p![osis::FieldId(1)]).get::<String>().unwrap().as_deref(), Some("small"));
    assert!(matches!(db.at(t, osis::DynamicAspectKey::untyped(k.clone())).path(p![osis::FieldId(0)]).get::<osis::Value>(), Err(Error::TooLarge { .. })));
    assert!(matches!(db.at(t, osis::DynamicAspectKey::untyped(k.clone())).path(p![osis::FieldId(2)]).get::<osis::Value>(), Err(Error::TooLarge { .. })));
}

// spec/data-model.md §6: a chunked large value reads back whole within the bound.
#[test]
fn large_value_round_trip_spec_data_model_6() {
    let db = db(1);
    let k = ak("t:blob.0");
    let big = Value::Bytes((0..osis::internals::schema::osis_base::format::CHUNK_THRESHOLD * 2).map(|i| (i % 251) as u8).collect());
    let mut w = db.write();
    let t = w.create().unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(k.clone())).set(&big).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(k)).get().unwrap(), Some(big));
}

// notes/api.md Writes: create with explicit first admin and membership; groups; add, remove,
// subgroups, delete.
// spec/data-model.md §8
#[test]
fn create_add_delete_spec_data_model_8() {
    let db = db(1);
    let mut w = db.write();
    let folder = w.create_in(db.me(), &[db.me()]).unwrap();
    w.group(db.me()).add(osis::Member::Subgroup(folder)).unwrap();
    let a = w.create_in(db.me(), &[folder, db.me()]).unwrap();
    let b = w.create().unwrap();
    w.at(a, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&Value::Int(1)).unwrap();
    w.commit().unwrap();
    assert_eq!(db.groups_of(a).unwrap().within.into_iter().collect::<BTreeSet<_>>(), BTreeSet::from([folder, db.me()]));
    assert!(db.groups_of(b).unwrap().within.is_empty());
    let mut w = db.write();
    w.group(folder).add(osis::Member::Item(b)).unwrap();
    w.commit().unwrap();
    let mut w = db.write();
    w.group(db.me()).remove(osis::Member::Item(a)).unwrap();
    w.commit().unwrap();
    assert_eq!(db.groups_of(a).unwrap().item_of, vec![folder]);
    let mut w = db.write();
    let s = w.create().unwrap();
    w.group(folder).add(osis::Member::Subgroup(s)).unwrap();
    w.group(s).add(osis::Member::Item(b)).unwrap();
    let sub = s;
    w.commit().unwrap();
    assert!(db.groups_of(b).unwrap().within.contains(&sub));
    assert!(db.groups_of(b).unwrap().within.contains(&folder));
    let mut w = db.write();
    w.delete(a).unwrap();
    w.commit().unwrap();
    assert!(db.groups_of(a).unwrap().within.is_empty());
    assert_eq!(db.at(a, osis::DynamicAspectKey::untyped(ak("t:x.0"))).get().unwrap(), None);
    // deleted: not known, though its creation stays held; a later write recreates it
    assert!(!db.has_content(a).unwrap() && db.created(a).unwrap().is_some());
    db.commit_set(a, osis::DynamicAspectKey::untyped(ak("t:x.0")), &Value::Int(2)).unwrap();
    assert!(db.has_content(a).unwrap());
    // an unknown group or first admin
    let mut w = db.write();
    let stranger = db_other_thing();
    assert_eq!(w.create_with_admin(stranger), Err(Error::UnknownThing { tid: stranger }));
    assert_eq!(w.create_in(db.me(), &[stranger]), Err(Error::UnknownThing { tid: stranger }));
}

// spec/permissions.md §1, notes/api.md Writes: rights are checked locally before signing:
// a node without write on a thing gets Permission; an unknown thing UnknownThing; nothing is
// committed.
#[test]
fn local_rights_check_spec_permissions_1() {
    let a = db(1);
    let b = db(2);
    let mut w = a.write();
    let t = w.create().unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&Value::Int(1)).unwrap();
    w.commit().unwrap();
    // b does not know t yet
    let mut w = b.write();
    w.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&Value::Int(2)).unwrap();
    assert_eq!(w.commit(), Err(Error::UnknownThing { tid: t }));
    deliver(&a, &b);
    assert_eq!(b.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).get().unwrap(), Some(Value::Int(1)));
    assert_eq!(b.role_on(t).unwrap(), None);
    let before = b.engine(|e| e.commit_ids().len());
    let mut w = b.write();
    w.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&Value::Int(2)).unwrap();
    assert_eq!(w.commit(), Err(Error::Permission { tid: t, needs: Role::Write }));
    assert_eq!(b.engine(|e| e.commit_ids().len()), before);
    // creating under someone else's actor
    let mut w = b.write();
    w.create_with_admin(a.me()).unwrap();
    assert!(matches!(w.commit(), Err(Error::Permission { .. })));
    // signals need write too
    let mut w = b.write();
    w.at(t, osis::DynamicAspectKey::untyped(ak("t:sig.0*"))).set(&Value::Int(1)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Permission { .. })));
}

// spec/permissions.md §1 (the record chain confers write), §5; notes/api.md Writes: one commit
// creates A, B under A and C under B; another node applying the commit holds all three.
// A thing under one the writer may not write is still refused.
#[test]
fn tree_in_one_commit_spec_permissions_1() {
    let a = db(1);
    let b = db(2);
    let mut w = a.write();
    let x = w.create().unwrap();
    let y = w.create_with_admin(x).unwrap();
    let z = w.create_with_admin(y).unwrap();
    for (i, t) in [x, y, z].into_iter().enumerate() {
        w.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&Value::Int(i as i64)).unwrap();
    }
    w.commit().unwrap().unwrap();
    deliver(&a, &b);
    for (i, t) in [x, y, z].into_iter().enumerate() {
        assert_eq!(b.grants(t).unwrap().get(&[a.me(), x, y][i]).map(|e| e.role), Some(Role::Admin), "its first admin");
        assert!(b.created(t).unwrap().is_some());
        assert_eq!(b.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).get().unwrap(), Some(Value::Int(i as i64)));
    }
    let before = b.engine(|e| e.commit_ids().len());
    let mut w = b.write();
    let p = w.create_with_admin(x).unwrap();
    w.create_with_admin(p).unwrap();
    assert!(matches!(w.commit(), Err(Error::Permission { .. })));
    let mut w = b.write();
    let p = w.create().unwrap();
    let q = w.create_with_admin(z).unwrap();
    w.create_with_admin(p).unwrap();
    w.create_with_admin(q).unwrap();
    assert!(matches!(w.commit(), Err(Error::Permission { .. })));
    assert_eq!(b.engine(|e| e.commit_ids().len()), before);
}

// notes/api.md Writes: role-class and synthetic aspects are not written by ops.
// spec/permissions.md §1
// spec/permissions.md §1 (role-class by admins): writer side
#[test]
fn role_class_refused_spec_permissions_1() {
    let db = db(1);
    let t = db.me();
    let mut w = db.write();
    assert!(matches!(w.at(t, osis::DynamicAspectKey::untyped(ak("label.0"))).remove(), Err(Error::Invalid(_))));
    assert!(matches!(w.at(t, osis::DynamicAspectKey::untyped(ak("roles.0"))).remove(), Err(Error::Invalid(_))));
    assert!(matches!(w.at(t, osis::DynamicAspectKey::untyped(ak("groups.0"))).remove(), Err(Error::Invalid(_))));
    // group.0 changes by the group calls alone: they check sync and clean up tied grants
    assert!(matches!(w.at(t, osis::internals::core_types::GROUP).set(&Group::default()), Err(Error::Invalid(_))));
    assert!(matches!(w.at(t, osis::internals::core_types::GROUP).path(p![osis::internals::GROUP_ITEMS]).add(&t), Err(Error::Invalid(_))));
    assert!(matches!(w.at(t, osis::DynamicAspectKey::untyped(ak("group.0"))).remove(), Err(Error::Invalid(_))));
    assert!(matches!(db.at(t, osis::DynamicAspectKey::untyped(ak("group.0"))).path(osis::p![]).edit_text().and_then(|s| {
        s.splice(0..0, "x")?;
        s.commit()
    }), Err(Error::Invalid(_))));
}

// spec/crdt.md §4.7: expiry is a hard bound however late the driver's Tick: from T on, no call
// sees the write, durable or ephemeral, with no tick run
#[test]
fn expired_unseen_before_tick_spec_crdt_4_7() {
    let c = clock();
    let db = osis::internals::create(cfg(1, MemStore::new(), &c)).unwrap();
    let (k, e) = (ak("t:msg.0"), ak("t:typing.0~"));
    let mut w = db.write();
    let t = w.create().unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(ak("t:kept.0"))).set(&s("kept")).unwrap();
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

// spec/commits.md §6, §5: per-write expiry kills the value at T; retention per write; purge
// drops the history and removes the aspect.
#[test]
fn expiry_retention_purge_spec_commits_5_6() {
    let c = clock();
    let db = osis::internals::create(cfg(1, MemStore::new(), &c)).unwrap();
    let (k, r) = (ak("t:msg.0"), ak("t:keep.0"));
    let mut w = db.write();
    let t = w.create().unwrap();
    let ret = osis::Retention { by: osis::internals::schema::PurgeBy::Writer, ..Default::default() };
    w.at(t, osis::DynamicAspectKey::untyped(r.clone())).retention(ret).set(&s("kept")).unwrap();
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

// notes/api.md Writes: `act_as` changes the header actor; the default is `me()`.
// spec/commits.md §1
#[test]
fn act_as_spec_commits_1() {
    let db = db(1);
    let mut w = db.write();
    let t = w.create().unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(ak("t:y.0"))).set(&Value::Int(0)).unwrap();
    let c1 = w.commit().unwrap().unwrap();
    let mut w = db.write();
    w.act_as(db.node());
    w.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&Value::Int(1)).unwrap();
    let c2 = w.commit().unwrap().unwrap();
    let actor = |c: osis::internals::RawCommitId| db.engine(|e| e.header(&c).unwrap().actor);
    assert_eq!((actor(c1.id.commit().unwrap()), actor(c2.id.commit().unwrap())), (db.me(), db.node()));
    // an empty write commits nothing
    assert_eq!(db.write().commit().unwrap(), None);
}

// notes/api.md Sync configuration and status: without a runtime the surface works locally,
// the stored peer list survives a reopen, and waiting for another node fails `Network`.
// spec: none (API surface, notes/api.md)
#[test]
fn local_sync_surface_spec_api_sync() {
    let c = clock();
    let store = MemStore::new();
    let db = osis::internals::create(cfg(1, store.clone(), &c)).unwrap();
    assert!(db.saved_peers().unwrap().is_empty());
    let st = db.status().unwrap();
    assert_eq!(st.groups.get(&db.me()).map(|g| g.state), Some(osis::SyncState::NoPeers));
    assert!("".parse::<osis::Address>().is_err());
    let a = osis::Address::new(&"quic://h:1".parse().unwrap(), [7; 32]);
    assert_eq!(a.to_string().parse::<osis::Address>().unwrap(), a);
    // a `quic://` URL without a port is :4040 (spec/sync.md §10), kept spelled out
    let d = osis::Address::new(&"quic://h:4040".parse().unwrap(), [7; 32]);
    assert_eq!(d.to_string().replace(":4040", "").parse::<osis::Address>().unwrap(), d);
    assert_eq!(osis::Address::new(&"quic://h".parse().unwrap(), [7; 32]), d);
    db.add_peer(&a).unwrap();
    assert!(matches!(common::block_on(db.wait_synced(osis::SyncScope::AllWithSavedPeers)), Err(Error::Network(_))));
    drop(db);
    let db = osis::internals::open(cfg(1, store, &c)).unwrap();
    assert_eq!(db.saved_peers().unwrap(), vec![a]);
}

// spec/data-model.md §9: `created.0` is typed by its exclusivity rule (admin or key), not the
// missing-field rule, so a run-time core key (`Osis::key`, the CLI's) reads it.
#[test]
fn created_reads_through_run_time_key_spec_data_model_9() {
    let db = osis::internals::create(osis::internals::Opening::memory()).unwrap();
    let mut w = db.write();
    let t = w.create().unwrap();
    w.commit().unwrap();
    let v = db.at(t, db.aspect_key("created.0").unwrap()).get().unwrap().unwrap();
    assert!(matches!(&v, Value::Map(m) if m.get(&Value::Int(0)) == Some(&Value::Tid(db.me()))));
}

// notes/api.md Large values, spec/data-model.md §6: a blob above the bound is read by stream
// (`Read + Seek`) and its length known without materializing it; `set_stream` writes one.
#[test]
fn stream_len_set_stream_spec_data_model_6() {
    use std::io::{Read, Seek, SeekFrom};
    let c = clock();
    let mut cf = cfg(1, MemStore::new(), &c);
    cf.app.read_limit = 64 * 1024;
    let db = osis::internals::create(cf).unwrap();
    let k = ak("t:blob.0");
    let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let mut w = db.write();
    let t = w.create().unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(k.clone())).path(osis::p![]).set_stream(&data[..]).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(k.clone())).get(), Err(Error::TooLarge { limit: 64 * 1024 }));
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(k.clone())).path(osis::p![]).byte_len().unwrap(), Some(300_000));
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
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(small.clone())).path(osis::p![]).byte_len().unwrap(), Some(5));
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(ak("t:none.0"))).path(osis::p![]).byte_len().unwrap(), None);
    db.commit_set(t, osis::DynamicAspectKey::untyped(ak("t:n.0")), &Value::Int(1)).unwrap();
    assert!(matches!(db.at(t, osis::DynamicAspectKey::untyped(ak("t:n.0"))).path(osis::p![]).byte_len(), Err(Error::Invalid(_))));
}

// spec/requirements.md (Offline and network), notes/api.md Diagnostics: a thing added only to a
// group no synced group holds gets `NotSynced`; one added to the (labeled) home group does not.
// spec: none (API surface, notes/api.md)
#[test]
fn not_synced_diagnostic_spec_api_diagnostics() {
    let db = db(1);
    let (tx, rx) = std::sync::mpsc::channel();
    let _sub = db.on_diagnostic(move |_, d| {
        if let osis::Diagnostic::NotSynced { thing, group, .. } = d {
            let _ = tx.send(std::iter::once(thing).chain(group).collect::<Vec<_>>());
        }
    }).unwrap();
    let mut w = db.write();
    let g = w.create().unwrap();
    // durable things: an ephemeral membership is no `NotSynced` matter (nothing leaves the
    // node anyway); placing a durable thing persists the group
    let home_item = w.create_with_content(db.me()).unwrap();
    w.group(db.me()).add(osis::Member::Item(home_item)).unwrap();
    let lost = w.create_with_content(db.me()).unwrap();
    w.group(g).add(osis::Member::Item(lost)).unwrap();
    w.commit().unwrap();
    db.settle();
    let got: Vec<osis::Tid> = rx.try_iter().flatten().collect();
    assert!(got.contains(&lost), "{got:?}");
    assert!(!got.contains(&home_item));
}

// notes/api.md Reads (knows), Watching: a deleted thing reads unknown (`created` still reports
// it); the delete reaches a thing watch, whose callback reads `has_content` false.
// spec: none (API surface, notes/api.md)
#[test]
fn deleted_reads_unknown_spec_api_reads() {
    let db = db(1);
    let mut w = db.write();
    let t = w.create_in(db.me(), &[db.me()]).unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&Value::Int(1)).unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(ak("t:y.0"))).set(&Value::Int(2)).unwrap();
    w.commit().unwrap();
    assert!(db.has_content(t).unwrap());
    let (tx, rx) = std::sync::mpsc::channel();
    let _sub = db.on_thing_change(t, move |db, c| {
        let _ = tx.send((c.ak, c.value, db.has_content(c.tid).unwrap()));
    }).unwrap();
    db.settle();
    let initial: Vec<_> = rx.try_iter().collect();
    assert!(initial.iter().all(|(_, _, known)| *known), "{initial:?}");
    let mut w = db.write();
    w.delete(t).unwrap();
    w.commit().unwrap();
    db.settle();
    let got: Vec<_> = rx.try_iter().collect();
    assert!(got.iter().any(|(ak, v, known)| ak.as_str() == "t:x.0" && *v == Ok(None) && !known), "{got:?}");
    assert!(!db.has_content(t).unwrap() && db.created(t).unwrap().is_some());
    assert!(!db.groups_of(db.me()).unwrap().item_of.contains(&t) && !db.at(db.me(), osis::internals::core_types::GROUP).get().unwrap().unwrap().items.contains(&t));
    // an unknown tid: not known, no creation
    let other = db_other_thing();
    assert!(!db.has_content(other).unwrap() && db.created(other).unwrap().is_none());
}

// notes/api.md Reads (groups_of), Writes (delete), spec/data-model.md §8: `groups_of` reports the
// groups listing a thing as an item and as a subgroup, and the transitive `groups.0`; deleting a
// group removes its memberships and the subgroup edges pointing at it.
#[test]
fn groups_of_relations_spec_data_model_8() {
    let db = db(1);
    let home = db.me();
    let (g1, g2, tag, x) = db.commit_with(|w| {
        let group = |w: &mut osis::Write<'_>| -> osis::Result<osis::Tid> {
            let g = w.create_in(db.me(), &[home])?;
            w.group(home).add(osis::Member::Subgroup(g))?;
            Ok(g)
        };
        let g1 = group(w)?;
        let g2 = group(w)?;
        let tag = w.create()?;
        w.group(g1).add(osis::Member::Item(tag))?;
        w.group(g1).add(osis::Member::Subgroup(tag))?;
        w.group(g2).add(osis::Member::Subgroup(tag))?;
        let x = w.create_with_content(db.me())?;
        w.group(tag).add(osis::Member::Item(x))?;
        Ok((g1, g2, tag, x))
    }).unwrap();
    let gs = db.groups_of(tag).unwrap();
    assert_eq!(gs.item_of, vec![g1]);
    assert_eq!(gs.subgroup_of.iter().copied().collect::<BTreeSet<_>>(), BTreeSet::from([g1, g2]));
    assert_eq!(gs.within.iter().copied().collect::<BTreeSet<_>>(), BTreeSet::from([g1, home]), "an item's groups and those above them; not g2, which it is only a subgroup of");
    let gx = db.groups_of(x).unwrap();
    assert_eq!(gx.item_of, vec![tag]);
    assert!(gx.subgroup_of.is_empty());
    assert_eq!(gx.within.iter().copied().collect::<BTreeSet<_>>(), BTreeSet::from([tag, g1, g2, home]));
    let mut w = db.write();
    w.delete(tag).unwrap();
    w.commit().unwrap();
    assert_eq!(db.groups_of(tag).unwrap(), osis::GroupsOf::default());
    for g in [g1, g2] {
        let d = db.at(g, osis::internals::core_types::GROUP).get().unwrap().unwrap();
        assert!(!d.items.contains(&tag) && !d.subgroups.contains(&tag), "{g}: {d:?}");
    }
    assert!(!db.has_content(tag).unwrap());
    assert_eq!(db.groups_of(x).unwrap().within, Vec::<osis::Tid>::new(), "its tag's group.0 went with it");
}

// notes/api.md Writes (place): a membership leaving a durable thing in no synced group while the
// target group's own aspects sync (an item of the synced home, no subgroup of it) fails before
// anything applies; the same commit adding the group as a subgroup succeeds; a node-local group
// (in no synced group) is allowed.
// spec: none (API surface, notes/api.md)
#[test]
fn membership_reaching_no_synced_group_fails_spec_api_writes() {
    let db = db(1);
    let home = db.me();
    let mut w = db.write();
    let g = w.create_in(db.me(), &[home]).unwrap();
    w.commit().unwrap();
    let mut w = db.write();
    let x = w.create_with_content(db.me()).unwrap();
    w.group(g).add(osis::Member::Item(x)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(m)) if m.contains("as a subgroup")));
    assert!(!db.has_content(x).unwrap() && db.created(x).unwrap().is_none(), "nothing applied");
    // a group with no synced group at all: node-local, allowed (a `NotSynced` diagnostic)
    let mut w = db.write();
    let l = w.create_with_content(db.me()).unwrap();
    let y = w.create_with_content(db.me()).unwrap();
    w.group(l).add(osis::Member::Item(y)).unwrap();
    let local = l;
    w.commit().unwrap();
    assert!(db.has_content(local).unwrap());
    // the fix: the group as a subgroup too, in the same commit
    let mut w = db.write();
    let x = w.create_with_content(db.me()).unwrap();
    w.group(g).add(osis::Member::Item(x)).unwrap();
    w.group(home).add(osis::Member::Subgroup(g)).unwrap();
    w.commit().unwrap();
    assert!(db.groups_of(x).unwrap().within.contains(&home));
}

// notes/api.md Handle (close): close() from a callback fails at once (it would wait on the
// dispatcher that runs it); from the app it returns once the node is closed.
// spec: none (API surface, notes/api.md)
#[test]
fn close_spec_api_handle() {
    let db = db(1);
    let (tx, rx) = std::sync::mpsc::channel();
    let k = ak("t:x.0");
    let mut w = db.write();
    let t = w.create().unwrap();
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
    let db = db(1);
    let other = db.clone();
    assert_eq!(db.close(), Ok(osis::Close::StillOpen { handles: 1 }));
    assert_eq!(other.close().unwrap(), osis::Close::Closed);
    for keep in [false, true] {
        let db = common::db(1);
        let k = ak("t:x.0");
        let mut w = db.write();
        let t = w.create().unwrap();
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
    let t = w.create().unwrap();
    w.commit().unwrap();
    let mut deep = Value::Int(0);
    for _ in 0..600 {
        deep = Value::List(vec![deep]);
    }
    assert!(db.commit_set(t, osis::DynamicAspectKey::untyped(ak("t:deep.0")), &deep).is_err(), "nesting past the depth limit accepted");
    let huge = Value::Str("x".repeat(string));
    db.commit_set(t, osis::DynamicAspectKey::untyped(ak("t:huge.0")), &huge).unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(ak("t:huge.0"))).get().unwrap(), Some(huge));
    let big: osis_base::ValueMap = (0..map).map(|i| (Value::Int(i), Value::Int(i))).collect();
    let _ = db.commit_set(t, osis::DynamicAspectKey::untyped(ak("t:map.0")), &Value::Map(big));
    // still working
    db.commit_set(t, osis::DynamicAspectKey::untyped(ak("t:x.0")), &Value::Int(1)).unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).get().unwrap(), Some(Value::Int(1)));
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
#[ignore = "tier 2"]
fn values_past_limits_huge_spec_data_model() {
    values_past_limits(8 << 20, 200_000);
}

// notes/api.md Writes (`GroupWrite::expires`, `expires`), spec/commits.md §6: a thing
// created with an expiring membership leaves its group at T by itself, its expiring value goes
// too; no `expires` is no expiry; a zero expiry is invalid; a commit returns the
// closure's value.
#[test]
fn expiring_membership_api_writes() {
    let c = clock();
    let db = osis::internals::create(cfg(1, MemStore::new(), &c)).unwrap();
    let x = ak("t:x.0");
    let minute = osis::Expiry::In(std::time::Duration::from_secs(60));
    // a thing's record does not expire: the thing first, then what expires
    let mut w = db.write();
    let gone = w.create().unwrap();
    w.at(gone, osis::DynamicAspectKey::untyped(ak("t:kept.0"))).set(&s("first")).unwrap();
    w.commit().unwrap();
    let mut w = db.write();
    w.expires(minute);
    w.group(db.me()).add(osis::Member::Item(gone)).unwrap();
    w.at(gone, osis::DynamicAspectKey::untyped(x.clone())).set(&s("bye")).unwrap();
    w.commit().unwrap();
    let mut w = db.write();
    let kept = w.create().unwrap();
    w.group(db.me()).add(osis::Member::Item(kept)).unwrap();
    w.at(kept, osis::DynamicAspectKey::untyped(x.clone())).set(&s("stays")).unwrap();
    w.commit().unwrap();
    let items = |db: &Osis| db.at(db.me(), osis::internals::core_types::GROUP).get().unwrap().unwrap().items;
    assert!(items(&db).contains(&gone) && items(&db).contains(&kept));
    c.advance(61_000);
    db.engine(|e| e.tick()).unwrap();
    assert!(!items(&db).contains(&gone), "the membership expired");
    assert!(items(&db).contains(&kept));
    assert_eq!(db.at(gone, osis::DynamicAspectKey::untyped(x.clone())).get().unwrap(), None);
    assert_eq!(db.at(kept, osis::DynamicAspectKey::untyped(x.clone())).get().unwrap(), Some(s("stays")));
    // not in the future: refused at commit
    for e in [osis::Expiry::In(std::time::Duration::ZERO), osis::Expiry::At(db.now().unwrap())] {
        let mut w = db.write();
        w.expires(e);
        w.at(kept, osis::DynamicAspectKey::untyped(x.clone())).set(&s("now")).unwrap();
        assert!(matches!(w.commit(), Err(Error::Invalid(_))));
    }
    // the last `expires` is the commit's
    let mut w = db.write();
    w.expires(osis::Expiry::In(std::time::Duration::ZERO));
    w.expires(minute);
    w.at(kept, osis::DynamicAspectKey::untyped(x.clone())).set(&s("again")).unwrap();
    assert!(w.commit().unwrap().is_some());
    // the `group.0` field constants are the ones `add` writes
    assert_eq!(db.at(db.me(), osis::internals::core_types::GROUP).path(p![osis::internals::GROUP_ITEMS]).get::<BTreeSet<osis::Tid>>().unwrap(), Some(items(&db)));
}

// spec/commits.md §2 (`created.0`); notes/api.md Reads (`created`, `now`): the creating commit with its time and
// receipt, the corrected clock.
#[test]
fn created_now_api_reads() {
    let c = clock();
    let db = osis::internals::create(cfg(1, MemStore::new(), &c)).unwrap();
    assert_eq!(db.now().unwrap(), osis::Time(T0));
    c.advance(5);
    assert_eq!(db.now().unwrap(), osis::Time(T0 + 5));
    let mut w = db.write();
    let t = w.create_with_content(db.me()).unwrap();
    let done = w.commit().unwrap().unwrap();
    let ci = db.created(t).unwrap().unwrap();
    assert_eq!((ci.id, ci.ts(), ci.node, ci.actor, ci.received), (done.id, done.ts(), db.node(), db.me(), osis::Time(T0 + 5)));
    assert_eq!(ci.shown(), osis::Time(T0 + 5));
    c.advance(5);
    db.commit_set(t, osis::DynamicAspectKey::untyped(ak("t:x.0")), &s("later")).unwrap();
    assert_eq!(db.created(t).unwrap().unwrap(), ci, "the creation, not the newest commit");
    let other = common::db(2);
    assert_eq!(db.created(other.me()).unwrap(), None);
}

// notes/api.md Reads (`changed`): a thing's last content change, shown at `min(ts, received)`:
// the creation until content changes; membership is no change of the item nor of the group's
// content; a node whose clock runs ahead dates its change at its receipt here, and the
// latest shown change wins over one with a higher `ts`; a delete is a change; an ephemeral
// thing reports its creation.
// spec: none (API surface, notes/api.md)
#[test]
fn changed_content_only_api_reads() {
    let (ca, cb) = (clock(), clock());
    let a = osis::internals::create(cfg(1, MemStore::new(), &ca)).unwrap();
    let j = osis::internals::pair(cfg(2, MemStore::new(), &cb), &a.pair_offer().unwrap()).unwrap();
    let (_, reply) = a.pair_accept(j.request()).unwrap();
    let b = j.finish(&reply).unwrap();
    let mut w = a.write();
    let t = w.create_with_content(a.me()).unwrap();
    w.group(a.me()).add(osis::Member::Item(t)).unwrap();
    w.commit().unwrap();
    assert_eq!(a.changed(t).unwrap(), a.created(t).unwrap());
    ca.advance(10);
    a.commit_set(t, osis::DynamicAspectKey::untyped(ak("t:x.0")), &s("1")).unwrap();
    let ch = a.changed(t).unwrap().unwrap();
    assert_eq!((ch.id, ch.shown()), (newest(&a, t).into(), osis::Time(T0 + 10)));
    assert_ne!(a.created(t).unwrap(), Some(ch));
    // membership: neither the item's nor the group's content
    let home = a.changed(a.me()).unwrap();
    ca.advance(10);
    let mut w = a.write();
    let g = w.create_with_content(a.me()).unwrap();
    w.commit().unwrap();
    let mut w = a.write();
    w.group(g).add(osis::Member::Item(t)).unwrap();
    w.group(a.me()).remove(osis::Member::Item(t)).unwrap();
    w.commit().unwrap();
    assert_eq!((a.changed(t).unwrap(), a.changed(a.me()).unwrap()), (Some(ch), home));
    // b's clock runs 30 min ahead (within MAX_DRIFT): its change shows at its receipt here
    deliver(&a, &b);
    cb.advance(30 * 60_000);
    b.commit_set(t, osis::DynamicAspectKey::untyped(ak("t:x.0")), &s("2")).unwrap();
    deliver(&b, &a);
    let ch = a.changed(t).unwrap().unwrap();
    assert_eq!((ch.node, ch.ts().wall_ms(), ch.shown()), (b.node(), osis::Time(T0 + 30 * 60_000), osis::Time(T0 + 20)));
    // a's next change: its ts follows b's (the clock rule), shown latest at its receipt
    ca.advance(10);
    a.commit_set(t, osis::DynamicAspectKey::untyped(ak("t:y.0")), &s("3")).unwrap();
    let ch = a.changed(t).unwrap().unwrap();
    assert_eq!((ch.node, ch.shown()), (a.node(), osis::Time(T0 + 30)));
    ca.advance(10);
    let mut w = a.write();
    w.delete(t).unwrap();
    w.commit().unwrap();
    assert!(!a.has_content(t).unwrap());
    assert_eq!(a.changed(t).unwrap().unwrap().shown(), osis::Time(T0 + 40), "a delete is a change");
    // an ephemeral write is no content change
    let e = a.commit_with(|w| w.create()).unwrap();
    a.commit_set(e, osis::DynamicAspectKey::untyped(ak("t:x.0~")), &s("typing")).unwrap();
    assert_eq!(a.changed(e).unwrap(), a.created(e).unwrap());
}

/// The newest held commit on `t` here.
fn newest(db: &Osis, t: osis::Tid) -> osis::internals::RawCommitId {
    db.commits(&osis::CommitQuery { scope: Some(osis::Scope::Thing(t)), limit: Some(1), ..Default::default() }).unwrap()[0].commit.id.commit().unwrap()
}

// spec/crdt.md §5.6 (a path op into a key with no live entry creates it; concurrent creations
// read as their join), notes/api.md Writes (path ops): two nodes of one account each add to a
// set under an absent map key; both elements survive the merge.
#[test]
fn path_op_into_absent_key_spec_crdt_5_6() {
    let c = clock();
    let a = osis::internals::create(cfg(1, MemStore::new(), &c)).unwrap();
    let j = osis::internals::pair(cfg(2, MemStore::new(), &c), &a.pair_offer().unwrap()).unwrap();
    let (_, reply) = a.pair_accept(j.request()).unwrap();
    let b = j.finish(&reply).unwrap();
    let r = ak("t:reactions.0");
    let mut w = a.write();
    let t = w.create_with_content(a.me()).unwrap();
    w.commit().unwrap();
    deliver(&a, &b);
    let mut w = a.write();
    w.at(t, osis::DynamicAspectKey::untyped(r.clone())).path(p!["m1"]).add(&s("x")).unwrap();
    w.commit().unwrap();
    let mut w = b.write();
    w.at(t, osis::DynamicAspectKey::untyped(r.clone())).path(p!["m1"]).add(&s("y")).unwrap();
    w.commit().unwrap();
    deliver(&a, &b);
    deliver(&b, &a);
    let want = Value::Map(osis_base::ValueMap::from([(s("m1"), Value::Set(osis_base::ValueSet::from([s("x"), s("y")])))]));
    assert_eq!(a.at(t, osis::DynamicAspectKey::untyped(r.clone())).get().unwrap(), Some(want.clone()));
    assert_eq!(b.at(t, osis::DynamicAspectKey::untyped(r)).get().unwrap(), Some(want));
}

// spec/commits.md §2 (`created.0` is carried by the first commit and by covering snapshots),
// notes/api.md Reads (`created`): a later compaction snapshot does not replace the creating
// commit; a node holding the snapshot without that commit reports none.
#[test]
fn created_not_a_snapshot_spec_commits_2() {
    let c = clock();
    let a = osis::internals::create(cfg(1, MemStore::new(), &c)).unwrap();
    let j = osis::internals::pair(cfg(2, MemStore::new(), &c), &a.pair_offer().unwrap()).unwrap();
    let (_, reply) = a.pair_accept(j.request()).unwrap();
    let b = j.finish(&reply).unwrap();
    let mut w = a.write();
    let t = w.create().unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&s("v")).unwrap();
    let done = w.commit().unwrap().unwrap();
    c.advance(60_000);
    let snap = a.engine(|e| e.snapshot(&t, &ak("t:x.0"))).unwrap().unwrap();
    assert_eq!(a.created(t).unwrap().unwrap().id, done.id);
    let pks = a.engine(|e| e.commit_ids().iter().filter(|id| **id != done.id.commit().unwrap()).filter_map(|id| e.package(id).unwrap()).collect::<Vec<_>>());
    for pk in pks {
        b.engine(|e| e.ingest(&pk.bytes, pk.blobs.clone()).unwrap());
    }
    assert!(b.engine(|e| e.header(&done.id.commit().unwrap())).is_none());
    let _ = snap;
    assert_eq!(b.created(t).unwrap(), None);
}

// notes/api.md Handle: peers with no runtime would never sync and nothing would say so: refused
// before anything is written. No peers stays local, and a runtime takes them.
// spec: none (API surface, notes/api.md)
#[test]
fn peers_without_a_runtime_are_refused() {
    let host = osis::Address::new(&"mem://nobody".parse().unwrap(), [7; 32]);
    let mut c = osis::internals::Opening::memory();
    c.hosts = vec![host.clone()];
    let r = osis::internals::create(c.clone());
    assert!(matches!(&r, Err(Error::Invalid(m)) if m.contains("runtime")), "{:?}", r.map(|_| ()));
    assert!(osis::internals::create(osis::internals::Opening::memory()).is_ok());
    c.runtime = osis::Runtime::Manual(osis::internals::ManualNet::new());
    assert!(osis::internals::create(c).is_ok());
}

// notes/api.md Handle: a relay is a node at one socket address; any other form is refused.
// spec: none (API surface, notes/api.md)
#[test]
fn relays_need_a_socket_address() {
    let key = [7u8; 32];
    for (url, ok) in [("peer://192.0.2.1:4040", true), ("peer://[2001:db8::1]:9", true), ("quic://example.org:4040", false), ("peer://example.org:4040", false), ("peer://x", false)] {
        let mut c = osis::internals::Opening::memory();
        c.relays = vec![osis::Address::new(&url.parse().unwrap(), key)];
        assert_eq!(osis::internals::create(c).is_ok(), ok, "{url}");
    }
}

// notes/api.md Sync configuration: `sync` of a group that has a label never moves it silently: its
// peers again, or none named, do nothing; other peers are refused.
// spec: none (API surface, notes/api.md)
#[test]
fn sync_refuses_other_peers() {
    let db = db(1);
    let (a, b) = (osis::Address::new(&"mem://a".parse().unwrap(), [1; 32]), osis::Address::new(&"mem://b".parse().unwrap(), [2; 32]));
    let mut w = db.write();
    let g = w.create().unwrap();
    w.commit().unwrap();
    db.sync(g, std::slice::from_ref(&a)).unwrap();
    db.sync(g, std::slice::from_ref(&a)).unwrap();
    db.sync(g, &[]).unwrap();
    assert!(matches!(db.sync(g, std::slice::from_ref(&b)), Err(Error::Invalid(_))));
    assert!(matches!(db.sync(g, &[a, b]), Err(Error::Invalid(_))));
}

// notes/api.md Reading: `has_content` is about content: a thing created and made durable with none reads
// `false`, like a deleted one, and still takes writes.
// spec: none (API surface, notes/api.md)
#[test]
fn knows_is_about_content() {
    let db = db(1);
    let k = ak("t:x.0");
    let mut w = db.write();
    let t = w.create().unwrap();
    w.commit().unwrap();
    db.sync(t, &[]).unwrap();
    assert!(db.created(t).unwrap().is_some(), "durable");
    assert!(!db.has_content(t).unwrap(), "no content yet");
    db.commit_set(t, osis::DynamicAspectKey::untyped(k.clone()), &Value::Int(1)).unwrap();
    assert!(db.has_content(t).unwrap());
    let mut w = db.write();
    w.delete(t).unwrap();
    w.commit().unwrap();
    assert!(!db.has_content(t).unwrap());
    db.commit_set(t, osis::DynamicAspectKey::untyped(k), &Value::Int(2)).unwrap();
    assert!(db.has_content(t).unwrap());
}

// notes/api.md Reading: `aspects` lists what reads as present: a register whose live write was
// purged reads absent, and is not listed.
// spec: none (API surface, notes/api.md)
#[test]
fn aspects_agrees_with_reads_after_a_purge() {
    let db = db(1);
    let k = ak("t:x.0");
    let mut w = db.write();
    let t = w.create().unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(k.clone())).set(&Value::Int(1)).unwrap();
    w.commit().unwrap();
    let mut w = db.write();
    w.at(t, osis::DynamicAspectKey::untyped(k.clone())).set(&Value::Int(2)).unwrap();
    let last = w.commit().unwrap().unwrap().id;
    let mut w = db.write();
    w.at(t, osis::DynamicAspectKey::untyped(k.clone())).purge(osis::Purge::Commit(last)).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(k.clone())).get().unwrap(), None);
    assert!(!db.aspects(t).unwrap().contains(&k));
}

// notes/api.md Group ops: the check is of what the cut took away. A cut below a subgroup of the synced
// group strands the same; a cut under a group that never synced strands nothing; deleting a tag tells
// of its items that went with it, never of the deleted tag.
// spec: none (API surface, notes/api.md)
#[test]
fn a_cut_tells_exactly_what_it_took_out_of_sync() {
    let db = db(1);
    let k = ak("t:x.0");
    let (tx, rx) = std::sync::mpsc::channel();
    db.on_diagnostic(move |_, d| {
        if let osis::Diagnostic::NotSynced { thing, group, .. } = d {
            let _ = tx.send(std::iter::once(thing).chain(group).collect::<Vec<_>>());
        }
    }).unwrap().detach();
    let group = |w: &mut osis::Write<'_>| {
        w.create().unwrap()
    };
    let synced = db.commit_with(|w| Ok(group(w))).unwrap();
    db.sync(synced, &[osis::Address::new(&"mem://a".parse().unwrap(), [1; 32])]).unwrap();
    let mut w = db.write();
    let (mid, low, plain, tag, far, dual) = (group(&mut w), group(&mut w), group(&mut w), group(&mut w), group(&mut w), group(&mut w));
    w.group(synced).add(osis::Member::Subgroup(mid)).unwrap();
    w.group(mid).add(osis::Member::Subgroup(low)).unwrap();
    w.group(plain).add(osis::Member::Subgroup(far)).unwrap();
    w.group(synced).add(osis::Member::Subgroup(tag)).unwrap();
    // `dual` is an item too: its own aspects keep syncing, its items do not
    w.group(synced).add(osis::Member::Subgroup(dual)).unwrap();
    w.group(synced).add(osis::Member::Item(dual)).unwrap();
    let (below, never, in_tag, also_synced, in_dual) = (w.create().unwrap(), w.create().unwrap(), w.create().unwrap(), w.create_with_admin(synced).unwrap(), w.create().unwrap());
    for t in [below, never, in_tag, also_synced, in_dual] {
        w.at(t, osis::DynamicAspectKey::untyped(k.clone())).set(&Value::Int(1)).unwrap();
    }
    w.group(low).add(osis::Member::Item(below)).unwrap();
    w.group(far).add(osis::Member::Item(never)).unwrap();
    w.group(tag).add(osis::Member::Item(in_tag)).unwrap();
    w.group(tag).add(osis::Member::Item(also_synced)).unwrap();
    w.group(synced).add(osis::Member::Item(also_synced)).unwrap();
    w.group(dual).add(osis::Member::Item(in_dual)).unwrap();
    w.commit().unwrap();
    db.settle();
    let _ = rx.try_iter().count();
    let told = |rx: &std::sync::mpsc::Receiver<Vec<osis::Tid>>| {
        db.settle();
        rx.try_iter().flatten().collect::<BTreeSet<osis::Tid>>()
    };
    let mut w = db.write();
    w.group(mid).remove(osis::Member::Subgroup(low)).unwrap();
    w.commit().unwrap();
    assert_eq!(told(&rx), BTreeSet::from([below]), "a level down");
    let mut w = db.write();
    w.group(plain).remove(osis::Member::Subgroup(far)).unwrap();
    w.commit().unwrap();
    assert_eq!(told(&rx), BTreeSet::new(), "it never synced");
    let mut w = db.write();
    w.delete(tag).unwrap();
    w.commit().unwrap();
    assert_eq!(told(&rx), BTreeSet::from([in_tag]), "its items, not the tag");
    let mut w = db.write();
    w.group(synced).remove(osis::Member::Subgroup(dual)).unwrap();
    w.commit().unwrap();
    assert_eq!(told(&rx), BTreeSet::from([in_dual]), "its items, not itself");
}

// notes/api.md Group ops: cutting a subgroup out of the synced group that was its only way there
// tells of the items it strands; an item still carried otherwise is not told of.
// spec: none (API surface, notes/api.md)
#[test]
fn cutting_a_subgroup_reports_what_it_strands() {
    let db = db(1);
    let k = ak("t:x.0");
    let (tx, rx) = std::sync::mpsc::channel();
    db.on_diagnostic(move |_, d| {
        if let osis::Diagnostic::NotSynced { thing, group, .. } = d {
            let _ = tx.send(std::iter::once(thing).chain(group).collect::<Vec<_>>());
        }
    }).unwrap().detach();
    let mut w = db.write();
    let g = w.create().unwrap();
    let synced = g;
    w.commit().unwrap();
    db.sync(synced, &[osis::Address::new(&"mem://a".parse().unwrap(), [1; 32])]).unwrap();
    let mut w = db.write();
    let sub = w.create().unwrap();
    w.group(synced).add(osis::Member::Subgroup(sub)).unwrap();
    let (stranded, kept) = (w.create().unwrap(), w.create_with_admin(synced).unwrap());
    for t in [stranded, kept] {
        w.at(t, osis::DynamicAspectKey::untyped(k.clone())).set(&Value::Int(1)).unwrap();
        w.group(sub).add(osis::Member::Item(t)).unwrap();
    }
    w.group(synced).add(osis::Member::Item(kept)).unwrap();
    w.commit().unwrap();
    db.settle();
    assert_eq!(rx.try_iter().collect::<Vec<_>>(), Vec::<Vec<osis::Tid>>::new());
    let mut w = db.write();
    w.group(synced).remove(osis::Member::Subgroup(sub)).unwrap();
    w.commit().unwrap();
    db.settle();
    let told: BTreeSet<osis::Tid> = rx.try_iter().flatten().collect();
    assert_eq!(told, BTreeSet::from([stranded]), "a subgroup is no member: its own aspects never went through this group");
}

// spec: none (client surface: notes/api.md Writes). The empty path is the whole value: each whole-value op there reads as the aspect's
// own, the collection ops take it too
#[test]
fn the_empty_path_is_the_whole_value() {
    let db = db(1);
    let (k, l) = (ak("t:x.0"), ak("t:s.0"));
    let t = db.commit_with(|w| {
        let t = w.create()?;
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

// spec: none (client surface: notes/api.md Reads). `members` lists a group's members as `groups_of` sees them: durable
// and ephemeral memberships alike; a thing that is no group has none
#[test]
fn members_list_a_groups_members() {
    let db = db(1);
    let mut w = db.write();
    let g = w.create().unwrap();
    let kept = w.create().unwrap();
    w.at(kept, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&Value::Int(1)).unwrap();
    w.at(g, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&Value::Int(1)).unwrap();
    w.group(g).add(osis::Member::Item(kept)).unwrap();
    w.commit().unwrap();
    let mut w = db.write();
    let (item, sub) = (w.create().unwrap(), w.create().unwrap());
    w.group(g).add(osis::Member::Item(item)).unwrap();
    w.group(g).add(osis::Member::Subgroup(sub)).unwrap();
    w.commit().unwrap();
    let mut want = vec![kept, item];
    want.sort();
    assert_eq!(db.items(g).unwrap(), want);
    assert_eq!(db.subgroups(g).unwrap(), vec![sub]);
    assert!(db.groups_of(item).unwrap().item_of.contains(&g), "the same answer from the other side");
    assert_eq!(db.items(kept).unwrap(), Vec::<osis::Tid>::new());
}

// spec/data-model.md §8: any thing becomes a group with its first member, item or subgroup, added
// in a later commit than its creation or in the same; an ephemeral one stays so
#[test]
fn a_first_member_makes_a_group() {
    let db = db(1);
    let (plain, other, a, b) = db
        .commit_with(|w| {
            let v = [w.create_with_content(db.me())?, w.create_with_content(db.me())?, w.create_with_content(db.me())?, w.create_with_content(db.me())?];
            Ok((v[0], v[1], v[2], v[3]))
        })
        .unwrap();
    assert_eq!(db.members(plain).unwrap(), vec![]);
    assert_eq!(db.at(plain, osis::internals::core_types::GROUP).get().unwrap(), None, "no group yet");
    let mut w = db.write();
    w.group(plain).add(osis::Member::Item(a)).unwrap();
    w.group(plain).add(osis::Member::Item(b)).unwrap();
    w.group(other).add(osis::Member::Subgroup(a)).unwrap();
    w.commit().unwrap();
    assert_eq!(db.members(plain).unwrap().len(), 2);
    assert!(db.groups_of(a).unwrap().item_of == vec![plain] && db.groups_of(a).unwrap().subgroup_of == vec![other]);
    assert_eq!(db.members(other).unwrap(), vec![osis::Member::Subgroup(a)]);
    // a thing both ways, each as itself
    let mut w = db.write();
    w.group(plain).add(osis::Member::Subgroup(a)).unwrap();
    w.commit().unwrap();
    assert_eq!(db.members(plain).unwrap().iter().filter(|m| m.tid() == a).count(), 2);
    // empty again, it stays a group
    let mut w = db.write();
    for m in db.members(other).unwrap() {
        w.group(other).remove(m).unwrap();
    }
    w.commit().unwrap();
    assert!(db.members(other).unwrap().is_empty() && db.at(other, osis::internals::core_types::GROUP).get().unwrap().is_some());
    // the acting actor's, whoever the commit acts as
    let mut w = db.write();
    let group_actor = w.create_with_content(db.me()).unwrap();
    w.commit().unwrap();
    let mut w = db.write();
    w.act_as(group_actor);
    let t = w.create().unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&Value::Int(1)).unwrap();
    w.commit().unwrap();
    assert_eq!(db.grants(t).unwrap().get(&group_actor).map(|e| e.role), Some(Role::Admin), "its first admin");
    // a new thing in the commit, its member new too: one commit
    let before = db.engine(|e| e.commit_ids().len());
    let (g, e) = db.commit_with(|w| {
        let (g, e) = (w.create()?, w.create()?);
        w.group(g).add(osis::Member::Item(e))?;
        Ok((g, e))
    }).unwrap();
    assert_eq!(db.engine(|e| e.commit_ids().len()), before + 1);
    assert_eq!(db.members(g).unwrap(), vec![osis::Member::Item(e)]);
}

/// A durable thing of `db`'s.
fn made(db: &Osis) -> osis::Tid {
    db.commit_with(|w| w.create_with_content(db.me())).unwrap()
}

// spec/data-model.md §8: two nodes each adding what is to them a first member both keep theirs, whichever arrives first
#[test]
fn first_members_on_two_nodes_both_stay() {
    let (a, b, _) = paired();
    let (g, x, y) = (made(&a), made(&a), made(&a));
    deliver(&a, &b);
    a.commit_with(|w| w.group(g).add(osis::Member::Item(x))).unwrap();
    b.commit_with(|w| w.group(g).add(osis::Member::Item(y))).unwrap();
    deliver(&a, &b);
    deliver(&b, &a);
    let both = {
        let mut v = vec![osis::Member::Item(x), osis::Member::Item(y)];
        v.sort_by_key(|m| m.tid());
        v
    };
    assert_eq!(a.members(g).unwrap(), both);
    assert_eq!(b.members(g).unwrap(), both);
}

// spec/data-model.md §8: members arriving between an add's call and its commit, unheard of at the call, are not erased by it
#[test]
fn a_member_arriving_during_a_commit_stays() {
    let (a, b, _) = paired();
    let (g, x, y) = (made(&a), made(&a), made(&a));
    deliver(&a, &b);
    a.commit_with(|w| w.group(g).add(osis::Member::Item(x))).unwrap();
    let mut w = b.write();
    w.group(g).add(osis::Member::Item(y)).unwrap();
    deliver(&a, &b);
    w.commit().unwrap();
    deliver(&b, &a);
    assert!(b.members(g).unwrap().contains(&osis::Member::Item(x)));
    assert!(a.members(g).unwrap().contains(&osis::Member::Item(x)), "the loss would spread");
}

// spec/data-model.md §8: a member added after a delete of the group counts, in one commit or from another node
#[test]
fn a_member_added_after_a_delete_stays() {
    let (a, b, c) = paired();
    let (g, x, y) = (made(&a), made(&a), made(&a));
    a.commit_with(|w| w.group(g).add(osis::Member::Item(x))).unwrap();
    a.commit_with(|w| {
        w.delete(g)?;
        w.group(g).add(osis::Member::Item(y))
    })
    .unwrap();
    assert_eq!(a.members(g).unwrap(), vec![osis::Member::Item(y)], "the same commit");
    let h = made(&a);
    a.commit_with(|w| w.group(h).add(osis::Member::Item(x))).unwrap();
    deliver(&a, &b);
    a.commit_with(|w| w.delete(h)).unwrap();
    c.advance(1000);
    b.commit_with(|w| w.group(h).add(osis::Member::Item(y))).unwrap();
    deliver(&a, &b);
    deliver(&b, &a);
    assert_eq!(a.members(h).unwrap(), vec![osis::Member::Item(y)], "a later add on another node");
    assert_eq!(b.members(h).unwrap(), vec![osis::Member::Item(y)]);
}

// spec/commits.md §6: what an expiring first member wrote leaves a later lasting member alone, in either field
#[test]
fn a_lasting_member_outlives_an_expiring_first() {
    let c = clock();
    let db = osis::internals::create(cfg(1, MemStore::new(), &c)).unwrap();
    let (g, x, s, y) = (made(&db), made(&db), made(&db), made(&db));
    let minute = osis::Expiry::In(std::time::Duration::from_secs(60));
    db.commit_with(|w| {
        w.expires(minute);
        w.group(g).add(osis::Member::Item(x))?;
        w.group(g).add(osis::Member::Subgroup(s))
    })
    .unwrap();
    db.commit_with(|w| w.group(g).add(osis::Member::Item(y))).unwrap();
    c.advance(61_000);
    db.engine(|e| e.tick()).unwrap();
    assert_eq!(db.members(g).unwrap(), vec![osis::Member::Item(y)]);
}

// spec/commits.md §7: a revert of a first member takes that member alone
#[test]
fn a_revert_of_a_first_member_takes_only_it() {
    let (a, b, _) = paired();
    let (g, x, y) = (made(&a), made(&a), made(&a));
    deliver(&a, &b);
    let done = commit_with(&a, |w| w.group(g).add(osis::Member::Item(x)));
    b.commit_with(|w| w.group(g).add(osis::Member::Item(y))).unwrap();
    deliver(&a, &b);
    deliver(&b, &a);
    a.revert(done.id).unwrap();
    deliver(&a, &b);
    assert_eq!(a.members(g).unwrap(), vec![osis::Member::Item(y)]);
    assert_eq!(b.members(g).unwrap(), vec![osis::Member::Item(y)]);
    let only = made(&a);
    let done = commit_with(&a, |w| w.group(only).add(osis::Member::Item(x)));
    a.revert(done.id).unwrap();
    assert!(a.members(only).unwrap().is_empty());
    a.commit_with(|w| w.group(only).add(osis::Member::Item(y))).unwrap();
    assert_eq!(a.members(only).unwrap(), vec![osis::Member::Item(y)], "and it can be one again");
}

// spec/commits.md §6, notes/api.md Writes: a subgroup expires as an item does; a removal in an expiring commit is refused
#[test]
fn membership_expires_item_or_subgroup_spec_commits_6() {
    let c = clock();
    let db = osis::internals::create(cfg(1, MemStore::new(), &c)).unwrap();
    let minute = osis::Expiry::In(std::time::Duration::from_secs(60));
    let mut w = db.write();
    let (g, t, s, kept) = (w.create_with_content(db.me()).unwrap(), w.create_with_content(db.me()).unwrap(), w.create_with_content(db.me()).unwrap(), w.create_with_content(db.me()).unwrap());
    w.commit().unwrap();
    let mut w = db.write();
    w.expires(minute);
    w.group(g).add(osis::Member::Item(t)).unwrap();
    w.group(g).add(osis::Member::Item(kept)).unwrap();
    w.group(g).remove(osis::Member::Item(kept)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(_))), "a removal does not expire");
    let mut w = db.write();
    w.expires(minute);
    w.delete(kept).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(_))), "nor a delete");
    assert_eq!(db.members(g).unwrap(), vec![], "nothing applied");
    let mut w = db.write();
    w.expires(minute);
    w.group(g).add(osis::Member::Item(t)).unwrap();
    w.group(g).add(osis::Member::Subgroup(s)).unwrap();
    w.commit().unwrap();
    assert_eq!(db.members(g).unwrap(), vec![osis::Member::Item(t), osis::Member::Subgroup(s)]);
    c.advance(61_000);
    db.engine(|e| e.tick()).unwrap();
    assert_eq!(db.members(g).unwrap(), vec![], "both left by themselves");
    let was = db.groups_of(t).unwrap();
    assert!(was.item_of.is_empty() && was.within.is_empty(), "the index with them: {was:?}");
    assert!(db.groups_of(s).unwrap().subgroup_of.is_empty());
    assert!(!db.engine(|e| e.closure(&g).contains(&t)), "and sync, which follows it");
    let mut w = db.write();
    w.group(g).add(osis::Member::Item(kept)).unwrap();
    w.commit().unwrap();
    assert_eq!(db.members(g).unwrap(), vec![osis::Member::Item(kept)], "and it can be one again");
}

// spec: none (client surface: notes/api.md Writes). One splice for a list and for text: replaces a range, an empty range inserts, no items delete
#[test]
fn splice_lists_and_text() {
    let db = db(1);
    let mut w = db.write();
    let t = w.create().unwrap();
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
    let db = db(1);
    let k = ak("t:m.0");
    let mut w = db.write();
    let t = w.create().unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(k.clone())).path(p!["a"]).set(&"one".to_string()).unwrap();
    w.commit().unwrap();
    let ed = db.at(t, osis::DynamicAspectKey::untyped(k.clone())).path(p!["a"]).edit_text().unwrap();
    assert_eq!(ed.text(), "one");
    ed.splice(3..3, "!").unwrap();
    ed.commit().unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(k.clone())).path(p!["a"]).get::<String>().unwrap().as_deref(), Some("one!"));
    assert!(matches!(db.at(t, osis::DynamicAspectKey::untyped(k)).path(osis::p![]).edit_text(), Err(Error::Invalid(_))), "the whole aspect is no string");
}

// spec/wire.md §10 (`MAX_URL_BYTES`), notes/api.md Sync configuration: a URL is checked when parsed and one peer has one address; a peer policy is typed and what the peer cannot run by is refused
#[test]
fn urls_and_serving_policy_are_typed() {
    let u: osis::Url = "quic://h".parse().unwrap();
    assert_eq!(u.as_str(), "quic://h:4040");
    assert_eq!(osis::Address::new(&u, [1; 32]).url(), u);
    for bad in ["", "no-scheme", "quic://", "://x", "quic://h#key", "quic://a b"] {
        assert!(matches!(bad.parse::<osis::Url>(), Err(Error::Invalid(_))), "{bad}");
    }
    let long = format!("quic://{}", "h".repeat(osis::internals::schema::osis_base::format::MAX_URL_BYTES));
    assert!(matches!(long.parse::<osis::Url>(), Err(Error::Invalid(_))));
    let db = db(1);
    let mut policy = osis::ServingPolicy { group_bytes: 77, ..Default::default() };
    osis::internals::host_limit(&mut policy, "deletes", 9).unwrap();
    db.set_serving(Some(osis::Serving { policy: policy.clone(), ..Default::default() })).unwrap();
    assert_eq!(db.serving().unwrap().unwrap().policy, policy);
    let mut bad = osis::ServingPolicy::default();
    assert!(osis::internals::host_limit(&mut bad, "max_queued_bytes", 1).is_err(), "a limit the host cannot run by");
}

// spec: none (API surface); notes/api.md Futures: what waits can go on any runtime's spawn
#[test]
fn waiting_calls_are_send() {
    fn send<T: Send>(_: T) {}
    fn all(db: Osis, login: osis::NodeLogin, link: osis::ShareLink, card: osis::ContactCard, id: osis::LinkId, t: osis::Tid, o: osis::SetRoleOpts) {
        send(db.wait_synced(osis::SyncScope::AllWithSavedPeers));
        send(db.redeem(&link));
        send(db.import_contact(&card));
        send(db.set_role(t, t, None, o));
        send(db.remove_node(t, o));
        send(db.revoke_link(id));
        send(db.connect_node(&login));
        send(db.group_source(t, osis::GroupSource::Local));
        send(Osis::connect(std::slice::from_ref(&login), osis::AppConfig::default()));
        send(Osis::connect_socket(std::path::Path::new("x"), osis::AppConfig::default()));
    }
    let _ = all;
}

// spec: none (API surface); notes/api.md Reads: a key tells an app the shape of its values, recursive types included, with no schema in sight
#[test]
fn value_type_describes_a_key_api_design() {
    use osis::ValueType as V;
    let db = db(1);
    db.register_schema(
        "t.osis",
        "version 1;
type tree = struct { 0 label: string, 1 kids: list<tree> };
type mood = enum { 0 calm, 1 odd(int) };
type rec = struct { 0 name: string, 1 when: timestamp, 2 span: duration, 3 nick: option<string>, 4 mood: mood, 5 tags: set<string>, 6 sizes: map<string, int>, 7 n: counter<int>, 8 body: markdown, 9 who: tid, 10 data: blob, 11 ok: bool, 12 x: float, 13 tree: tree };
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
    assert!(matches!(by("who").ty.get(), V::Thing));
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
    assert_eq!(osis::DynamicAspectKey::untyped(ak("t:rec.0")).value_type(), None);
    assert_eq!(key.default_retention(), osis::Retention::default());
}

// spec: none (API surface); notes/api.md Commits: a commit's and a place's text form names what it was made from, an entry's or a commit's, and anything else is `Invalid`
#[test]
fn commit_and_place_text_forms_api_design() {
    let db = db(1);
    let k = db.aspect_key("t:x.0").unwrap();
    let mut w = db.write();
    let t = w.create().unwrap();
    w.at(t, k.clone()).set(&Value::Int(1)).unwrap();
    let done = w.commit().unwrap().unwrap();
    assert_eq!(done.id.to_string().parse::<osis::CommitId>().unwrap(), done.id);
    let page = db.at(t, k.clone()).history(osis::HistoryFrom::Newest, 1).unwrap();
    let pos = page.entries[0].pos();
    assert_eq!(pos, done.pos());
    assert_eq!(pos.to_string().parse::<osis::HistoryPos>().unwrap(), pos);
    assert_eq!(pos.commit(), Some(done.id));
    assert_eq!(pos.at(), done.written);
    // a time's place comes before what was written then, and names no commit
    let at = osis::HistoryPos::time(done.written);
    assert!(at < pos);
    assert_eq!(at.commit(), None);
    assert_eq!(db.at(t, k.clone()).history(osis::HistoryFrom::After(at), 1).unwrap().entries[0].pos(), pos);
    // past the last moment a place can name: still a place, after everything
    assert!(osis::HistoryPos::time(osis::Time(u64::MAX)) > pos);
    let m = w_ephemeral(&db, t);
    assert_eq!(m.to_string().parse::<osis::CommitId>().unwrap(), m);
    for bad in ["", "abc", "ephemeral:", "ephemeral:00:1", "ephemeral:zz:1"] {
        assert!(matches!(bad.parse::<osis::CommitId>(), Err(Error::Invalid(_))), "{bad}");
    }
    for bad in ["", "1", "x/y", "1/abc"] {
        assert!(matches!(bad.parse::<osis::HistoryPos>(), Err(Error::Invalid(_))), "{bad}");
    }
}

fn w_ephemeral(db: &Osis, t: osis::Tid) -> osis::CommitId {
    let mut w = db.write();
    w.at(t, db.aspect_key("t:cursor.0~").unwrap()).set(&Value::Int(1)).unwrap();
    w.commit().unwrap().unwrap().id
}

// spec: none (API surface); notes/api.md Serving: an admission id is opaque text, asked of a group; a group that does not sync has none; a peer policy says what it takes on in plain limits, and the rest stays by name
#[test]
fn sync_ids_and_serving_policy_api_design() {
    let db = db(1);
    let mut w = db.write();
    let g = w.create().unwrap();
    w.at(g, osis::core::NAME).set(&"g".to_string()).unwrap();
    w.commit().unwrap();
    assert!(db.sync_ids(g).unwrap().is_empty(), "not synced");
    for bad in ["", "abc", "zz"] {
        assert!(matches!(bad.parse::<osis::SyncId>(), Err(Error::Invalid(_))), "{bad}");
    }
    let id: osis::SyncId = "00112233445566778899aabbccddeeff".parse().unwrap();
    assert_eq!(id.to_string(), "00112233445566778899aabbccddeeff");
    let mut p = osis::ServingPolicy { groups: 7, ..Default::default() };
    osis::internals::host_limit(&mut p, "connections", 3).unwrap();
    osis::internals::host_limit(&mut p, "deletes", 9).unwrap();
    assert!(osis::internals::host_limit(&mut p, "no_such_limit", 1).is_err());
    // one limit, one place, by either name
    osis::internals::host_limit(&mut p, "cap_bytes", 55).unwrap();
    assert_eq!(p.group_bytes, 55);
    assert!(!osis::internals::host_limits_unshown(&p).contains_key("cap_bytes"));
    p.group_bytes = osis::ServingPolicy::default().group_bytes;
    db.set_serving(Some(osis::Serving { admitted: [id].into(), caps: [(id, osis::ServingCaps { entries: 1, bytes: 2 })].into(), policy: p.clone(), ..Default::default() })).unwrap();
    let h = db.serving().unwrap().unwrap();
    assert_eq!((h.policy.groups, h.policy.connections, osis::internals::host_limits_unshown(&h.policy).get("deletes").copied()), (7, 3, Some(9)));
    assert_eq!(h.policy, p);
    assert!(h.admitted.contains(&id) && h.caps.contains_key(&id));
}

// spec/data-model.md §5 (standard types); notes/api.md Keys: a description sees through aliases and generics to what a type is, `timestamp`, `date` and the like by their own words; what a schema cannot declare never reaches it
#[test]
fn value_type_through_aliases_and_generics_api_design() {
    use osis::ValueType as V;
    let db = db(1);
    db.register_schema(
        "t.osis",
        "version 1;
type stamp = timestamp;
type stamp2 = stamp;
type box<T> = struct { 0 v: T };
type maybe = option<int>;
type rec = struct { 0 a: stamp2, 1 b: box<stamp>, 2 c: maybe, 3 d: date, 4 e: localtime, 5 f: map<string, option<duration>>, 6 g: list<box<box<date>>> };
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
        assert!(matches!(db.register_schema("bad.osis", &format!("version 1; {bad}")), Err(Error::Invalid(_))), "{bad}");
    }
}

// spec: none (API surface); notes/api-design.md No leaks: what a public signature shows can be named: a type in a public field or a call's error is exported
#[test]
fn what_public_signatures_show_can_be_named_api_design() {
    let h = osis::History::Keep { until: osis::Time(0), after_replaced: std::time::Duration::ZERO };
    let r = osis::core::Required { retention: osis::Retention { by: osis::PurgeBy::default(), history: Some(h) }, expires: None };
    assert_eq!(r.retention.history, Some(h));
    let e = osis::PathError::new(osis::Path::root(), osis::PathErrorKind::Mismatch { expected: "x" });
    assert!(matches!(e.kind, osis::PathErrorKind::Mismatch { .. }));
    let _: Result<osis::Ak, osis::AkError> = osis::Ak::new("t:x.0");
    let _: Result<osis::Tid, osis::TidParseError> = osis::Tid::parse("nope");
}

// spec: none (API surface); notes/api.md History: a place past the last time there is names the end, whichever way a page goes; a place's text round-trips, a time's too, and a time's names no change
#[test]
fn history_place_of_any_time_api_design() {
    use osis::{HistoryFrom as F, HistoryPos as P, Time};
    let db = db(1);
    let k = osis::DynamicAspectKey::untyped(ak("t:x.0"));
    let t = db.commit_with(|w| w.create()).unwrap();
    let c = commit_with(&db, |w| w.at(t, k.clone()).set(&Value::Int(1)));
    let page = |f| db.at(t, k.clone()).history(f, 10).unwrap().entries.len();
    let (zero, end) = (P::time(Time(0)), P::time(Time(u64::MAX)));
    assert!(zero < c.pos() && c.pos() < end);
    assert_eq!((page(F::Before(end)), page(F::After(end))), (1, 0));
    assert_eq!((page(F::Before(zero)), page(F::After(zero))), (0, 1));
    assert_eq!(page(F::After(P::time(c.written))), 1, "from that moment on");
    assert_eq!(page(F::Before(P::time(c.written))), 0, "stamped earlier");
    assert_eq!((page(F::Before(c.pos())), page(F::After(c.pos()))), (0, 0), "neither bound counts itself");
    for p in [zero, end, P::time(c.written), c.pos()] {
        assert_eq!(p.to_string().parse::<P>().unwrap(), p);
    }
    assert_eq!((end.commit(), c.pos().commit()), (None, Some(c.id)));
}
