//! Handle, keys, reads, the `Write` batch, rights, errors (notes/api.md Handle, Keys, Reads,
//! Writes, Errors, Footguns closed).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common::watched;
use crate::common::TestWrites as _;
use osis::AspectKey as _;
use osis::internals::Internals as _;
use crate::common;
use common::*;
use crate::common::{CreateIn, CreateExpiringIn};
use osis::schema::core_types::Group;
use osis::{Error, MemStore, Osis, Role, Value, core, p};
use std::collections::{BTreeMap, BTreeSet};

#[allow(clippy::all, dead_code)]
mod notes {
    use osis::schema as osis_schema;
    include!("../../../schema/tests/gen/notes.rs");
}
use notes::{Task, task};

fn s(x: &str) -> Value {
    Value::Str(x.into())
}

fn task(title: &str) -> Task {
    Task { title: title.into(), done: false, tags: BTreeSet::new(), priority: None, due: None, status: None, weight: osis::schema::osis_base::Float::new(1.0) }
}

// notes/api.md Handle and lifecycle: a new database has a node, a person actor and its home
// group; reopening the store gives the same identity.
// spec: none (API surface, notes/api.md)
#[test]
fn create_and_reopen_spec_api_handle() {
    let store = MemStore::new();
    let c = clock();
    let (node, me) = {
        let db = Osis::create(cfg(1, store.clone(), &c)).unwrap().0;
        assert_ne!(db.me(), db.node());
        assert_eq!(db.at(db.me(), core::GROUP).get().unwrap(), Some(Group::default()));
        assert_eq!(db.role_on(db.me()).unwrap(), Some(Role::Admin));
        (db.node(), db.me())
    };
    fn send_sync<T: Send + Sync>() {}
    send_sync::<Osis>();
    send_sync::<osis::Subscription>();
    let db = Osis::open(cfg(2, store, &c)).unwrap();
    assert_eq!((db.node(), db.me()), (node, me));
    // an empty store is not a database
    assert!(Osis::open(cfg(3, MemStore::new(), &c)).is_err());
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
    w.at(n, notes::TITLE).set(&"Groceries".to_string()).unwrap();
    w.at(n, notes::TASKS).set(&vec![task("milk"), task("eggs")]).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(n, notes::TITLE).get().unwrap().as_deref(), Some("Groceries"));
    assert_eq!(db.at(n, notes::TASKS).get().unwrap().unwrap()[1].title, "eggs");
    let at = db.at(n, notes::TASKS);
    assert_eq!(at.path(p![1, task::TITLE]).get::<String>().unwrap().as_deref(), Some("eggs"));
    assert_eq!(at.path(p![5, task::TITLE]).get::<osis::Value>().unwrap(), None);
    // path op on a typed list element
    let mut w = db.write();
    w.at(n, notes::TASKS).path(p![0, task::DONE]).set(&true).unwrap();
    w.commit().unwrap();
    assert!(db.at(n, notes::TASKS).get().unwrap().unwrap()[0].done);
    // mistyped data: untyped write of an int under a string AK
    let (tx, diags) = std::sync::mpsc::channel();
    let _d = db.on_diagnostic(move |_, d| {
        if d.kind == osis::DiagnosticKind::Mismatch {
            tx.send(d).unwrap();
        }
    }).unwrap();
    db.commit_set(n, ak("note:title.0"), &Value::Int(3)).unwrap();
    assert_eq!(db.at(n, notes::TITLE).get().unwrap(), None, "absent, not an error");
    let d = recv(&diags);
    assert_eq!((d.tids, d.detail.as_str()), (vec![n], "note:title.0: type error at (root): expected string"));
    assert_eq!(db.at(n, ak("note:title.0")).get().unwrap(), Some(Value::Int(3)));
    // one element of another shape (as a newer version's enum case would be)
    let Value::List(mut l) = notes::TASKS.encode(&vec![task("milk"), task("eggs")]) else { panic!() };
    let Some(Value::Map(m)) = l.get_mut(1) else { panic!() };
    m.insert(Value::Int(1), Value::Int(7));
    db.commit_set(n, ak("note:tasks.0"), &Value::List(l)).unwrap();
    assert_eq!(db.at(n, notes::TASKS).get().unwrap(), None);
    let at = db.at(n, notes::TASKS);
    assert_eq!(at.path(p![0, task::TITLE]).get::<String>().unwrap().as_deref(), Some("milk"));
    assert_eq!(at.path(p![1, task::TITLE]).get::<String>().unwrap(), None);
    assert_eq!(at.path(p![1]).get::<osis::Value>().unwrap(), None);
    assert_eq!(at.path(p![0]).get::<Task>().unwrap().map(|t| t.title).as_deref(), Some("milk"));
    // a path the schema does not have is the caller's mistake: an error
    assert!(matches!(at.path(osis::Path(vec![osis::Step::Index(0), osis::Step::Field(99)])).get::<Value>(), Err(Error::Type { .. })));
    // a typed write is validated against the writer's schema
    let mut w = db.write();
    let e = w.at(n, notes::TASKS).path(p![0, task::DONE]).set(&s("no")).unwrap_err();
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
        if d.kind == osis::DiagnosticKind::Mismatch {
            tx.send(d).unwrap();
        }
    }).unwrap();
    let bogus = Value::link(osis::schema::osis_base::Link { hash: [3; 32], blob: osis::schema::osis_base::BlobId([4; 32]), suite: 1, key: [5; 32] });
    db.commit_set(n, ak("note:pinned.0"), &Value::Map([(bogus, Value::Int(1))].into_iter().collect())).unwrap();
    assert_eq!(db.at(n, notes::PINNED).get().unwrap(), None, "absent, not an error");
    assert_eq!(recv(&diags).tids, vec![n]);
}

// spec/data-model.md §6 (unreadable link): a link where the type takes one whose value cannot be read (one names
// no blob, one a blob under another thing's dedup secret) reads as absent at its own position, with an `Unreadable` diagnostic; the
// rest of the aspect reads, by typed and untyped reads, watches and `on_change` alike (one such
// set element failed every read of the aspect `blob missing`).
#[test]
fn unreadable_link_reads_absent_at_its_position_spec_dm_6() {
    use osis::schema::osis_base::{BlobId, Link};
    let db = db(1);
    let mut w = db.write();
    let n = w.create_in(db.me(), &[db.me()]).unwrap();
    w.commit().unwrap();
    let (tx, diags) = std::sync::mpsc::channel();
    let _d = db.on_diagnostic(move |_, d| {
        if d.kind == osis::DiagnosticKind::Unreadable {
            tx.send(d).unwrap();
        }
    }).unwrap();
    let watch = watched(&db, n, notes::TASKS).unwrap();
    let (ctx, changes) = std::sync::mpsc::channel();
    let _sub = db.at(n, notes::TASKS).on_change(move |_, c| ctx.send(c.value).unwrap()).unwrap();
    assert_eq!(recv(&changes), Ok(None), "the initial call");
    // two tasks, the first's tags holding a link that names no blob
    let tasks = vec![task("a"), task("b")];
    db.commit_set(n, notes::TASKS, &tasks).unwrap();
    // calls coalesce (a late call reads the latest state): take this one before the next write
    assert_eq!(recv(&changes), Ok(Some(tasks.clone())));
    let Some(Value::List(mut raw)) = db.at(n, ak("note:tasks.0")).get().unwrap() else { panic!() };
    let Value::Map(first) = &mut raw[0] else { panic!() };
    let bogus = Value::link(Link { hash: [3; 32], blob: BlobId([4; 32]), suite: 1, key: [5; 32] });
    // and a held blob of another thing's large value: under that thing's dedup secret
    let mut w = db.write();
    let m = w.create().unwrap();
    w.commit().unwrap();
    db.commit_set(m, ak("t:big.0"), &s(&"x".repeat(200 << 10))).unwrap();
    let foreign = db.engine(|e| e.get(&m, &ak("t:big.0"))).unwrap().unwrap();
    assert!(matches!(foreign, Value::Link(_)));
    first.insert(Value::Int(task::TAGS.0 as i64), Value::Set([s("kept"), bogus, foreign].into_iter().collect()));
    db.commit_set(n, ak("note:tasks.0"), &Value::List(raw)).unwrap();
    let mut want = tasks.clone();
    want[0].tags = ["kept".to_string()].into();
    assert_eq!(db.at(n, notes::TASKS).get().unwrap(), Some(want.clone()), "the rest reads");
    let d = recv(&diags);
    assert_eq!(d.tids, vec![n]);
    assert!(d.detail.contains("blob missing") && d.detail.contains("verification failed"), "{}", d.detail);
    assert_eq!(db.at(n, notes::TASKS).path(p![0, task::TAGS]).get::<BTreeSet<String>>().unwrap(), Some(["kept".to_string()].into()));
    assert_eq!(db.at(n, notes::TASKS).path(p![1]).get::<Task>().unwrap(), Some(task("b")));
    // on_change: the write with the link; the watch holds it too
    assert_eq!(recv(&changes), Ok(Some(want.clone())));
    assert_eq!(watch.current(), Ok(Some(want)));
    // at the aspect root: the aspect reads absent, not an error
    let k = ak("t:x.0");
    db.commit_set(n, k.clone(), &Value::link(Link { hash: [6; 32], blob: BlobId([7; 32]), suite: 1, key: [8; 32] })).unwrap();
    assert_eq!(db.at(n, k).get().unwrap(), None);
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
    db.commit_set(n, k.clone(), &big).unwrap();
    let Some(Value::Link(l)) = db.engine(|e| e.get(&n, &k)).unwrap() else { panic!() };
    let bytes = db.engine(|e| e.blob(&l.blob)).unwrap().unwrap();
    db.engine(|e| {
        e.run(|tx| {
            tx.txn.delete_blob(&l.blob);
            Ok(())
        })
    })
    .unwrap();
    let watch = watched(&db, n, k.clone()).unwrap();
    assert_eq!(watch.current(), Ok(None), "not held: absent");
    let (tx, changes) = std::sync::mpsc::channel();
    let _sub = db.at(n, k.clone()).on_change(move |_, c| tx.send((c.value, c.source)).unwrap()).unwrap();
    assert_eq!(recv(&changes), (Ok(None), osis::Source::Initial));
    db.engine(|e| e.put_blobs(vec![(l.blob, bytes)])).unwrap();
    assert_eq!(recv(&changes), (Ok(Some(big.clone())), osis::Source::Derived(osis::Cause::Fetched)));
    assert_eq!(watch.current(), Ok(Some(big)));
}

// notes/api.md Keys: a schema registered at run time types `Key` reads (reader defaults) and
// validates writes; unknown AKs stay untyped.
// spec: none (API surface, notes/api.md)
#[test]
fn registered_schema_key_spec_api_keys() {
    let db = db(1);
    db.register_schema("notes.osis", notes::SCHEMA.source()).unwrap();
    assert!(db.register_schema("bad.osis", "schema nonsense").is_err());
    // a schema declaring a core AK is the core schema's business, not an app's
    assert!(db.register_schema("core.osis", "version 1;\naspect name.0: int;\n").is_err());
    assert_eq!(db.key("name.0").unwrap().schema().map(|s| s.declares_core()), Some(true));
    // a later registration of an AK types it
    db.register_schema("n2.osis", "version 5;\naspect note:title.0: int;\n").unwrap();
    assert_eq!(db.key("note:title.0").unwrap().schema().map(|s| s.version), Some(5));
    db.register_schema("notes.osis", notes::SCHEMA.source()).unwrap();
    let title = db.key("note:title.0").unwrap();
    assert!(title.schema().is_some());
    assert!(db.key("other:x.0").unwrap().schema().is_none());
    let mut w = db.write();
    let n = w.create().unwrap();
    assert!(matches!(w.at(n, title.clone()).set(&Value::Int(1)), Err(Error::Type { .. })));
    w.at(n, title.clone()).set(&s("x")).unwrap();
    // a task without `weight` reads with the declared default
    let mut t = BTreeMap::new();
    t.insert(Value::Int(1), s("a"));
    t.insert(Value::Int(2), Value::Bool(false));
    t.insert(Value::Int(3), Value::Set(osis_base::ValueSet::new()));
    w.at(n, ak("note:tasks.0")).set(&Value::List(vec![Value::Map(t.into_iter().collect())])).unwrap();
    w.commit().unwrap();
    let tasks = db.key("note:tasks.0").unwrap();
    let v = db.at(n, tasks).path(p![0, task::WEIGHT]).get::<osis::Value>().unwrap();
    assert_eq!(v, Some(Value::float(1.0)));
}

// notes/api.md Reads: absent aspects and unknown things read as None, never as errors.
// spec: none (API surface, notes/api.md)
#[test]
fn absent_reads_none_spec_api_reads() {
    let db = db(1);
    let other = db_other_thing();
    assert_eq!(db.at(other, ak("a:b.0")).get().unwrap(), None);
    assert_eq!(db.at(db.me(), ak("a:b.0")).get().unwrap(), None);
    assert!(!db.knows(other).unwrap());
    assert_eq!(db.role_on(other).unwrap(), None);
}

fn db_other_thing() -> osis::Tid {
    let o = db(9);
    o.me()
}

fn titles(db: &Osis, t: osis::Tid) -> Vec<String> {
    db.at(t, notes::TASKS).get().unwrap().unwrap().into_iter().map(|x| x.title).collect()
}

// notes/api.md Writes: whole-value ops and every path op.
// spec: none (API surface, notes/api.md)
#[test]
fn write_ops_spec_api_writes() {
    let db = db(1);
    let mut w = db.write();
    let t = w.create().unwrap();
    let (m, st, c) = (ak("t:map.0"), ak("t:set.0"), ak("t:reg.0"));
    w.at(t, m.clone()).path(p!["a"]).set(&1i64).unwrap();
    w.at(t, m.clone()).path(p!["b"]).set(&2i64).unwrap();
    w.at(t, st.clone()).path(p![]).add(&"x".to_string()).unwrap();
    w.at(t, st.clone()).path(p![]).add(&"y".to_string()).unwrap();
    w.at(t, notes::TASKS).set(&vec![task("a"), task("b"), task("c")]).unwrap();
    w.at(t, c.clone()).set(&s("one")).unwrap();
    w.commit().unwrap();
    let mut w = db.write();
    w.at(t, m.clone()).path(p!["a"]).remove().unwrap();
    w.at(t, m.clone()).path(p!["b"]).set(&5i64).unwrap();
    w.at(t, st.clone()).path(p!["x"]).remove().unwrap();
    w.at(t, notes::TASKS).path(p![]).splice(0..0, &[task("z")]).unwrap();
    w.at(t, c.clone()).overwrite(&s("two")).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, m.clone()).get().unwrap(), Some(Value::Map(osis_base::ValueMap::from([(s("b"), Value::Int(5))]))));
    assert_eq!(db.at(t, st.clone()).get().unwrap(), Some(Value::Set(osis_base::ValueSet::from([s("y")]))));
    assert_eq!(titles(&db, t), ["z", "a", "b", "c"]);
    assert_eq!(db.at(t, c.clone()).get().unwrap(), Some(s("two")));
    let mut w = db.write();
    w.at(t, notes::TASKS).path(p![]).splice(0..1, ()).unwrap();
    w.at(t, notes::TASKS).path(p![2]).remove().unwrap();
    w.commit().unwrap();
    let mut w = db.write();
    w.at(t, notes::TASKS).path(p![]).move_range(0..1, 1).unwrap();
    w.commit().unwrap();
    assert_eq!(titles(&db, t), ["b", "a"]);
    let mut w = db.write();
    w.at(t, m.clone()).path(p!["b"]).remove().unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, m.clone()).get().unwrap(), Some(Value::Map(osis_base::ValueMap::new())));
    // counter, max, enum case, text splice through typed keys
    let mut w = db.write();
    w.at(t, notes::VIEWS).path(osis::Path::root()).contribute(&2i64).unwrap();
    w.at(t, notes::VIEWS).path(osis::Path::root()).contribute(&3i64).unwrap();
    w.at(t, notes::BODY).set(&"hello world".to_string()).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, notes::VIEWS).get().unwrap(), Some(5));
    let mut w = db.write();
    w.at(t, notes::BODY).path(p![]).splice(0..5, "goodbye").unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, notes::BODY).get().unwrap().as_deref(), Some("goodbye world"));
    db.commit_set(t, notes::TASKS, &vec![task("a")]).unwrap();
    let mut w = db.write();
    w.at(t, notes::TASKS).path(p![0, task::PRIORITY]).set(&Value::Enum(1, Some(Box::new(Value::Enum(2, None))))).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, notes::TASKS).get().unwrap().unwrap()[0].priority, Some(notes::Priority::High));
    // max: observe keeps the largest contribution
    db.register_schema("t.osis", "version 1;\naspect t:max.0: max<int>;\n").unwrap();
    let mx = db.key("t:max.0").unwrap();
    let mut w = db.write();
    w.at(t, mx.clone()).path(p![]).contribute(&7i64).unwrap();
    w.at(t, mx.clone()).path(p![]).contribute(&3i64).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, mx).get().unwrap(), Some(Value::Int(7)));
    // remove the aspect; a field cannot be removed by path
    let mut w = db.write();
    w.at(t, c.clone()).remove().unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, c).get().unwrap(), None);
    let mut w = db.write();
    assert!(matches!(w.at(t, notes::TASKS).path(p![0, task::DONE]).remove(), Err(Error::Invalid(_))));
    // a set element is atomic
    assert!(matches!(w.at(t, st).path(osis::Path(vec![osis::Step::Elem(s("y"))])).set(&1i64), Err(Error::Invalid(_))));
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
    w.at(t, k.clone()).set(&form("a", "b")).unwrap();
    w.commit().unwrap();
    let shown = db.at(t, k.clone()).get().unwrap().unwrap();
    // meanwhile another writer changes field 1
    let mut w = db.write();
    w.at(t, k.clone()).path(p![Value::Int(1)]).set(&s("B")).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, k.clone()).get().unwrap(), Some(form("a", "B")));
    // the user edits field 0 of what they were shown
    let edited = form("A", "b");
    let mut w = db.write();
    w.at(t, k.clone()).edit(&shown, &edited).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, k.clone()).get().unwrap(), Some(form("A", "B")));
    // `set` of the edited value clobbers the concurrent change
    let mut w = db.write();
    w.at(t, k.clone()).path(p![Value::Int(1)]).set(&s("C")).unwrap();
    w.commit().unwrap();
    db.commit_set(t, k.clone(), &edited).unwrap();
    assert_eq!(db.at(t, k).get().unwrap(), Some(form("A", "b")));
}

// notes/api.md Reads, Large values: a value above the materialization bound fails TooLarge
// (chunked or not); a path read of a small position of the same aspect works.
// spec/data-model.md §6
#[test]
fn materialization_bound_spec_data_model_6() {
    let c = clock();
    let mut cf = cfg(1, MemStore::new(), &c);
    cf.materialize_limit = 64 * 1024;
    let db = Osis::create(cf).unwrap().0;
    let k = ak("t:doc.0");
    let big = Value::Bytes(vec![7u8; osis::schema::osis_base::format::CHUNK_THRESHOLD + 1000]);
    let mid = Value::Bytes(vec![1u8; 100 * 1024]);
    let mut w = db.write();
    let t = w.create().unwrap();
    w.at(t, k.clone()).set(&Value::Map(osis_base::ValueMap::from([(Value::Int(0), big), (Value::Int(1), s("small")), (Value::Int(2), mid)]))).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, k.clone()).get(), Err(Error::TooLarge { limit: 64 * 1024 }));
    assert_eq!(db.at(t, k.clone()).path(p![osis::FieldId(1)]).get::<String>().unwrap().as_deref(), Some("small"));
    assert!(matches!(db.at(t, k.clone()).path(p![osis::FieldId(0)]).get::<osis::Value>(), Err(Error::TooLarge { .. })));
    assert!(matches!(db.at(t, k.clone()).path(p![osis::FieldId(2)]).get::<osis::Value>(), Err(Error::TooLarge { .. })));
}

// spec/data-model.md §6: a chunked large value reads back whole within the bound.
#[test]
fn large_value_round_trip_spec_data_model_6() {
    let db = db(1);
    let k = ak("t:blob.0");
    let big = Value::Bytes((0..osis::schema::osis_base::format::CHUNK_THRESHOLD * 2).map(|i| (i % 251) as u8).collect());
    let mut w = db.write();
    let t = w.create().unwrap();
    w.at(t, k.clone()).set(&big).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, k).get().unwrap(), Some(big));
}

// notes/api.md Writes: create with explicit owner and placement; groups; place, unplace,
// subgroups, delete.
// spec/data-model.md §8
#[test]
fn create_place_delete_spec_data_model_8() {
    let db = db(1);
    let mut w = db.write();
    let folder = w.create_in(db.me(), &[db.me()]).unwrap();
    let a = w.create_in(db.me(), &[folder, db.me()]).unwrap();
    let b = w.create().unwrap();
    w.at(a, ak("t:x.0")).set(&Value::Int(1)).unwrap();
    w.commit().unwrap();
    assert_eq!(db.groups_of(a).unwrap().within.into_iter().collect::<BTreeSet<_>>(), BTreeSet::from([folder, db.me()]));
    assert!(db.groups_of(b).unwrap().within.is_empty());
    let mut w = db.write();
    w.group(folder).add(osis::Member::Item(b)).unwrap();
    w.group(db.me()).remove(osis::Member::Item(a)).unwrap();
    w.commit().unwrap();
    assert_eq!(db.groups_of(a).unwrap().within, vec![folder]);
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
    assert_eq!(db.at(a, ak("t:x.0")).get().unwrap(), None);
    // deleted: not known, though its creation stays held; a later write recreates it
    assert!(!db.knows(a).unwrap() && db.created(a).unwrap().is_some());
    db.commit_set(a, ak("t:x.0"), &Value::Int(2)).unwrap();
    assert!(db.knows(a).unwrap());
    // an unknown group or owner
    let mut w = db.write();
    let stranger = db_other_thing();
    assert_eq!(w.create_owned_by(stranger), Err(Error::UnknownThing { tid: stranger }));
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
    w.at(t, ak("t:x.0")).set(&Value::Int(1)).unwrap();
    w.commit().unwrap();
    // b does not know t yet
    let mut w = b.write();
    w.at(t, ak("t:x.0")).set(&Value::Int(2)).unwrap();
    assert_eq!(w.commit(), Err(Error::UnknownThing { tid: t }));
    deliver(&a, &b);
    assert_eq!(b.at(t, ak("t:x.0")).get().unwrap(), Some(Value::Int(1)));
    assert_eq!(b.role_on(t).unwrap(), None);
    let before = b.engine(|e| e.commit_ids().len());
    let mut w = b.write();
    w.at(t, ak("t:x.0")).set(&Value::Int(2)).unwrap();
    assert_eq!(w.commit(), Err(Error::Permission { tid: t, needs: Role::Write }));
    assert_eq!(b.engine(|e| e.commit_ids().len()), before);
    // creating under someone else's actor
    let mut w = b.write();
    w.create_owned_by(a.me()).unwrap();
    assert!(matches!(w.commit(), Err(Error::Permission { .. })));
    // signals need write too
    let mut w = b.write();
    w.at(t, ak("t:sig.0*")).set(&Value::Int(1)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Permission { .. })));
}

// spec/permissions.md §1 (the owner chain confers write), §5; notes/api.md Writes: one batch
// creates A, B owned by A and C owned by B; another node applying the commit holds all three.
// A thing owned by one the writer may not write is still refused.
#[test]
fn tree_in_one_batch_spec_permissions_1() {
    let a = db(1);
    let b = db(2);
    let mut w = a.write();
    let x = w.create().unwrap();
    let y = w.create_owned_by(x).unwrap();
    let z = w.create_owned_by(y).unwrap();
    for (i, t) in [x, y, z].into_iter().enumerate() {
        w.at(t, ak("t:x.0")).set(&Value::Int(i as i64)).unwrap();
    }
    w.commit().unwrap().unwrap();
    deliver(&a, &b);
    for (i, t) in [x, y, z].into_iter().enumerate() {
        assert_eq!(b.owner_of(t).unwrap(), Some([a.me(), x, y][i]));
        assert!(b.created(t).unwrap().is_some());
        assert_eq!(b.at(t, ak("t:x.0")).get().unwrap(), Some(Value::Int(i as i64)));
    }
    let before = b.engine(|e| e.commit_ids().len());
    let mut w = b.write();
    let p = w.create_owned_by(x).unwrap();
    w.create_owned_by(p).unwrap();
    assert!(matches!(w.commit(), Err(Error::Permission { .. })));
    let mut w = b.write();
    let p = w.create().unwrap();
    let q = w.create_owned_by(z).unwrap();
    w.create_owned_by(p).unwrap();
    w.create_owned_by(q).unwrap();
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
    assert!(matches!(w.at(t, ak("label.0")).remove(), Err(Error::Invalid(_))));
    assert!(matches!(w.at(t, ak("roles.0")).remove(), Err(Error::Invalid(_))));
    assert!(matches!(w.at(t, ak("groups.0")).remove(), Err(Error::Invalid(_))));
    // group.0 changes by the group calls alone: they check sync and clean up tied edges
    assert!(matches!(w.at(t, core::GROUP).set(&Group::default()), Err(Error::Invalid(_))));
    assert!(matches!(w.at(t, core::GROUP).path(p![core::group::ITEMS]).add(&t), Err(Error::Invalid(_))));
    assert!(matches!(w.at(t, ak("group.0")).remove(), Err(Error::Invalid(_))));
    assert!(matches!(db.at(t, ak("group.0")).path(osis::p![]).edit_text().and_then(|s| {
        s.splice(0..0, "x")?;
        s.commit()
    }), Err(Error::Invalid(_))));
}

// spec/crdt.md §4.7: expiry is a hard bound however late the driver's Tick: from T on, no call
// sees the write, durable or ephemeral, with no tick run
#[test]
fn expired_unseen_before_tick_spec_crdt_4_7() {
    let c = clock();
    let db = Osis::create(cfg(1, MemStore::new(), &c)).unwrap().0;
    let (k, e) = (ak("t:msg.0"), ak("t:typing.0~"));
    let mut w = db.write();
    let t = w.create().unwrap();
    w.at(t, k.clone()).expires(osis::Expiry::In(std::time::Duration::from_secs(60))).set(&s("hi")).unwrap();
    w.at(t, e.clone()).expires(osis::Expiry::In(std::time::Duration::from_secs(60))).set(&s("typing")).unwrap();
    w.commit().unwrap();
    c.advance(59_999);
    assert_eq!((db.at(t, k.clone()).get().unwrap(), db.at(t, e.clone()).get().unwrap()), (Some(s("hi")), Some(s("typing"))));
    c.advance(1);
    assert_eq!((db.at(t, k).get().unwrap(), db.at(t, e).get().unwrap()), (None, None));
}

// spec/commits.md §6, §5: per-write expiry kills the value at T; retention per write; purge
// drops the history and removes the aspect.
#[test]
fn expiry_retention_purge_spec_commits_5_6() {
    let c = clock();
    let db = Osis::create(cfg(1, MemStore::new(), &c)).unwrap().0;
    let (k, r) = (ak("t:msg.0"), ak("t:keep.0"));
    let mut w = db.write();
    let t = w.create().unwrap();
    w.at(t, k.clone()).expires(osis::Expiry::In(std::time::Duration::from_secs(60))).set(&s("hi")).unwrap();
    let ret = osis::Retention { by: osis::schema::PurgeBy::Writer, ..Default::default() };
    w.at(t, r.clone()).retention(ret).set(&s("kept")).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, k.clone()).get().unwrap(), Some(s("hi")));
    c.advance(61_000);
    db.engine(|e| e.tick()).unwrap();
    assert_eq!(db.at(t, k.clone()).get().unwrap(), None);
    // expiry in the past is invalid at commit
    let mut w = db.write();
    assert!(matches!(w.at(t, k.clone()).expires(osis::Expiry::At(osis::WallMs(T0))).set(&s("late")), Err(Error::Invalid(_))));
    drop(w);
    // purge
    let mut w = db.write();
    w.at(t, r.clone()).purge(osis::Purge::All).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, r.clone()).get().unwrap(), None);
}

// notes/api.md Writes: `act_as` changes the header actor; the default is `me()`.
// spec/commits.md §1
#[test]
fn act_as_spec_commits_1() {
    let db = db(1);
    let mut w = db.write();
    let t = w.create().unwrap();
    w.at(t, ak("t:y.0")).set(&Value::Int(0)).unwrap();
    let c1 = w.commit().unwrap().unwrap();
    let mut w = db.write();
    w.act_as(db.node());
    w.at(t, ak("t:x.0")).set(&Value::Int(1)).unwrap();
    let c2 = w.commit().unwrap().unwrap();
    let actor = |c: osis::CommitId| db.engine(|e| e.header(&c).unwrap().actor);
    assert_eq!((actor(c1.id.commit().unwrap()), actor(c2.id.commit().unwrap())), (db.me(), db.node()));
    // an empty write commits nothing
    assert_eq!(db.write().commit().unwrap(), None);
}

// notes/api.md Sync configuration and status: without a runtime the surface works locally,
// the stored host list survives a reopen, and waiting for another node fails `Network`.
// spec: none (API surface, notes/api.md)
#[test]
fn local_sync_surface_spec_api_sync() {
    let c = clock();
    let store = MemStore::new();
    let db = Osis::create(cfg(1, store.clone(), &c)).unwrap().0;
    assert!(db.hosts().unwrap().is_empty());
    let st = db.status().unwrap();
    assert_eq!(st.groups.get(&db.me()).map(|g| g.state), Some(osis::SyncState::NoHosts));
    assert!("".parse::<osis::HostAddr>().is_err());
    let a = osis::HostAddr::new("quic://h:1", [7; 32]);
    assert_eq!(a.to_string().parse::<osis::HostAddr>().unwrap(), a);
    // a `quic://` URL without a port is :4040 (spec/sync.md §10), kept spelled out
    let d = osis::HostAddr::new("quic://h:4040", [7; 32]);
    assert_eq!(d.to_string().replace(":4040", "").parse::<osis::HostAddr>().unwrap(), d);
    assert_eq!(osis::HostAddr::new("quic://h", [7; 32]), d);
    db.add_host(&a).unwrap();
    assert!(matches!(common::block_on(db.wait_synced(osis::SyncScope::All, std::time::Duration::from_secs(1))), Err(Error::Network(_))));
    drop(db);
    let db = Osis::open(cfg(1, store, &c)).unwrap();
    assert_eq!(db.hosts().unwrap(), vec![a]);
}

// spec/data-model.md §9: `created.0` is typed by its exclusivity rule (owner or key), not the
// missing-field rule, so a run-time core key (`Osis::key`, the CLI's) reads it.
#[test]
fn created_reads_through_run_time_key_spec_data_model_9() {
    let db = Osis::create(osis::Config::memory()).unwrap().0;
    let mut w = db.write();
    let t = w.create().unwrap();
    w.commit().unwrap();
    let v = db.at(t, db.key("created.0").unwrap()).get().unwrap().unwrap();
    assert!(matches!(&v, Value::Map(m) if m.get(&Value::Int(0)) == Some(&Value::Tid(db.me()))));
}

// notes/api.md Large values, spec/data-model.md §6: a blob above the bound is read by stream
// (`Read + Seek`) and its length known without materializing it; `set_stream` writes one.
#[test]
fn stream_len_set_stream_spec_data_model_6() {
    use std::io::{Read, Seek, SeekFrom};
    let c = clock();
    let mut cf = cfg(1, MemStore::new(), &c);
    cf.materialize_limit = 64 * 1024;
    let db = Osis::create(cf).unwrap().0;
    let k = ak("t:blob.0");
    let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let mut w = db.write();
    let t = w.create().unwrap();
    w.at(t, k.clone()).path(osis::p![]).set_stream(&data[..]).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, k.clone()).get(), Err(Error::TooLarge { limit: 64 * 1024 }));
    assert_eq!(db.at(t, k.clone()).path(osis::p![]).len().unwrap(), Some(300_000));
    let mut st = db.at(t, k.clone()).path(osis::p![]).stream().unwrap().unwrap();
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
    db.commit_set(t, small.clone(), &s("hello")).unwrap();
    assert_eq!(db.at(t, small.clone()).path(osis::p![]).len().unwrap(), Some(5));
    assert_eq!(db.at(t, ak("t:none.0")).path(osis::p![]).len().unwrap(), None);
    db.commit_set(t, ak("t:n.0"), &Value::Int(1)).unwrap();
    assert!(matches!(db.at(t, ak("t:n.0")).path(osis::p![]).len(), Err(Error::Invalid(_))));
}

// spec/requirements.md (Offline and network), notes/api.md Diagnostics: a thing placed only in a
// group no synced group holds gets `NotSynced`; one placed in the (labeled) home group does not.
// spec: none (API surface, notes/api.md)
#[test]
fn not_synced_diagnostic_spec_api_diagnostics() {
    let db = db(1);
    let (tx, rx) = std::sync::mpsc::channel();
    let _sub = db.on_diagnostic(move |_, d| {
        if d.kind == osis::DiagnosticKind::NotSynced {
            let _ = tx.send(d.tids);
        }
    }).unwrap();
    let mut w = db.write();
    let g = w.create().unwrap();
    // durable things: an ephemeral placement is no `NotSynced` matter (nothing leaves the
    // device anyway); placing a durable thing persists the group
    let home_item = w.create_durable(db.me()).unwrap();
    w.group(db.me()).add(osis::Member::Item(home_item)).unwrap();
    let lost = w.create_durable(db.me()).unwrap();
    w.group(g).add(osis::Member::Item(lost)).unwrap();
    w.commit().unwrap();
    db.settle();
    let got: Vec<osis::Tid> = rx.try_iter().flatten().collect();
    assert!(got.contains(&lost), "{got:?}");
    assert!(!got.contains(&home_item));
}

// notes/api.md Reads (knows), Watching: a deleted thing reads unknown (`created` still reports
// it); the delete reaches a thing watch, whose callback reads `knows` false.
// spec: none (API surface, notes/api.md)
#[test]
fn deleted_reads_unknown_spec_api_reads() {
    let db = db(1);
    let mut w = db.write();
    let t = w.create_in(db.me(), &[db.me()]).unwrap();
    w.at(t, ak("t:x.0")).set(&Value::Int(1)).unwrap();
    w.at(t, ak("t:y.0")).set(&Value::Int(2)).unwrap();
    w.commit().unwrap();
    assert!(db.knows(t).unwrap());
    let (tx, rx) = std::sync::mpsc::channel();
    let _sub = db.watch_thing(t, move |db, c| {
        let _ = tx.send((c.ak, c.value, db.knows(c.tid).unwrap()));
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
    assert!(!db.knows(t).unwrap() && db.created(t).unwrap().is_some());
    assert!(!db.groups_of(db.me()).unwrap().item_of.contains(&t) && !db.at(db.me(), core::GROUP).get().unwrap().unwrap().items.contains(&t));
    // an unknown tid: not known, no creation
    let other = db_other_thing();
    assert!(!db.knows(other).unwrap() && db.created(other).unwrap().is_none());
}

// notes/api.md Reads (groups_of), Writes (delete), spec/data-model.md §8: `groups_of` reports the
// groups listing a thing as an item and as a subgroup, and the transitive `groups.0`; deleting a
// group removes its placements and the subgroup edges pointing at it.
#[test]
fn groups_of_relations_spec_data_model_8() {
    let db = db(1);
    let home = db.me();
    let (g1, g2, tag, x) = db.batch(|w| {
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
        let x = w.create_durable(db.me())?;
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
        let d = db.at(g, core::GROUP).get().unwrap().unwrap();
        assert!(!d.items.contains(&tag) && !d.subgroups.contains(&tag), "{g}: {d:?}");
    }
    assert!(!db.knows(tag).unwrap());
    assert_eq!(db.groups_of(x).unwrap().within, Vec::<osis::Tid>::new(), "its tag's group.0 went with it");
}

// notes/api.md Writes (place): a placement leaving a durable thing in no synced group while the
// target group's own aspects sync (an item of the synced home, no subgroup of it) fails before
// anything applies, also when a durable write persists an ephemeral thing placed there; the
// same batch adding the group as a subgroup succeeds; a device-local group (in no synced
// group) and a thing that stays ephemeral are allowed.
// spec: none (API surface, notes/api.md)
#[test]
fn placement_reaching_no_synced_group_fails_spec_api_writes() {
    let db = db(1);
    let home = db.me();
    let mut w = db.write();
    let g = w.create_in(db.me(), &[home]).unwrap();
    w.commit().unwrap();
    let mut w = db.write();
    let x = w.create_durable(db.me()).unwrap();
    w.group(g).add(osis::Member::Item(x)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(m)) if m.contains("as a subgroup")));
    assert!(!db.knows(x).unwrap() && db.created(x).unwrap().is_none(), "nothing applied");
    // an ephemeral thing stays on this device anyway
    let mut w = db.write();
    let e = w.create_in(db.me(), &[g]).unwrap();
    w.commit().unwrap();
    assert!(db.groups_of(e).unwrap().item_of.contains(&g));
    // ... until a durable write persists it with that placement: the same check
    let r = db.commit_set(e, ak("t:x.0"), &Value::Int(1));
    assert!(matches!(&r, Err(Error::Invalid(m)) if m.contains("as a subgroup")), "{r:?}");
    assert_eq!(db.created(e).unwrap().unwrap().commit, None, "still ephemeral");
    // a group with no synced group at all: device-local, allowed (a `NotSynced` diagnostic)
    let mut w = db.write();
    let l = w.create_durable(db.me()).unwrap();
    let y = w.create_durable(db.me()).unwrap();
    w.group(l).add(osis::Member::Item(y)).unwrap();
    let local = l;
    w.commit().unwrap();
    assert!(db.knows(local).unwrap());
    // the fix: the group as a subgroup too, in the same batch
    let mut w = db.write();
    let x = w.create_durable(db.me()).unwrap();
    w.group(g).add(osis::Member::Item(x)).unwrap();
    w.group(home).add(osis::Member::Subgroup(g)).unwrap();
    w.commit().unwrap();
    assert!(db.groups_of(x).unwrap().within.contains(&home));
}

// notes/api.md Handle (close): close() from a callback fails at once (it would wait on the
// dispatcher that runs it); from the app it returns once the database is closed.
// spec: none (API surface, notes/api.md)
#[test]
fn close_spec_api_handle() {
    let db = db(1);
    let (tx, rx) = std::sync::mpsc::channel();
    let k = ak("t:x.0");
    let mut w = db.write();
    let t = w.create().unwrap();
    w.commit().unwrap();
    let sub = db.at(t, k).on_change(move |db, _| {
        let _ = tx.send(db.clone().close());
    }).unwrap();
    assert!(matches!(recv(&rx), Err(Error::Invalid(_))));
    drop(sub);
    let weak = db.downgrade();
    assert_eq!(db.close().unwrap(), osis::Close::Closed);
    assert!(weak.upgrade().is_none(), "closed when close() returns");
}

// notes/api.md Handle (close): close() tells the truth about the database. Another handle
// keeps it open: `Close::StillOpen` at once, no error. A callback still running: close waits for it, then the
// database is closed; a callback that kept a clone of its handle: StillOpen.
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
        db.at(t, k.clone()).on_change(move |db, c| {
            if c.source == osis::Source::Initial {
                return;
            }
            let _ = entered.send(());
            let _ = wait.lock().unwrap().recv();
            if keep {
                *kept2.lock().unwrap() = Some(db.clone());
            }
        }).unwrap().detach();
        db.commit_set(t, k.clone(), &Value::Int(1)).unwrap();
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
/// entries; the database errs or accepts, never panics, and keeps working.
fn values_past_limits(string: usize, map: i64) {
    let db = db(1);
    let mut w = db.write();
    let t = w.create().unwrap();
    w.commit().unwrap();
    let mut deep = Value::Int(0);
    for _ in 0..600 {
        deep = Value::List(vec![deep]);
    }
    assert!(db.commit_set(t, ak("t:deep.0"), &deep).is_err(), "nesting past the depth limit accepted");
    let huge = Value::Str("x".repeat(string));
    db.commit_set(t, ak("t:huge.0"), &huge).unwrap();
    assert_eq!(db.at(t, ak("t:huge.0")).get().unwrap(), Some(huge));
    let big: osis_base::ValueMap = (0..map).map(|i| (Value::Int(i), Value::Int(i))).collect();
    let _ = db.commit_set(t, ak("t:map.0"), &Value::Map(big));
    // still working
    db.commit_set(t, ak("t:x.0"), &Value::Int(1)).unwrap();
    assert_eq!(db.at(t, ak("t:x.0")).get().unwrap(), Some(Value::Int(1)));
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
// created with an expiring placement leaves its group at T by itself, its expiring value goes
// too; no `expires` is no expiry; a zero expiry is invalid; a batch returns the
// closure's value.
#[test]
fn expiring_placement_api_writes() {
    let c = clock();
    let db = Osis::create(cfg(1, MemStore::new(), &c)).unwrap().0;
    let (x, d) = (ak("t:x.0"), Some(std::time::Duration::from_secs(60)));
    let minute = osis::Expiry::In(std::time::Duration::from_secs(60));
    let mut w = db.write();
    let t = w.create_expiring_in(db.me(), db.me(), d).unwrap();
    w.at(t, x.clone()).expires(minute).set(&s("bye")).unwrap();
    let gone = t;
    w.commit().unwrap();
    let mut w = db.write();
    let t = w.create_expiring_in(db.me(), db.me(), None).unwrap();
    w.at(t, x.clone()).set(&s("stays")).unwrap();
    let kept = t;
    w.commit().unwrap();
    let items = |db: &Osis| db.at(db.me(), core::GROUP).get().unwrap().unwrap().items;
    assert!(items(&db).contains(&gone) && items(&db).contains(&kept));
    c.advance(61_000);
    db.engine(|e| e.tick()).unwrap();
    assert!(!items(&db).contains(&gone), "the placement expired");
    assert!(items(&db).contains(&kept));
    assert_eq!(db.at(gone, x.clone()).get().unwrap(), None);
    assert_eq!(db.at(kept, x.clone()).get().unwrap(), Some(s("stays")));
    let mut w = db.write();
    assert!(matches!(w.create_expiring_in(db.me(), db.me(), Some(std::time::Duration::ZERO)), Err(Error::Invalid(_))));
    assert!(matches!(w.at(kept, x.clone()).expires(osis::Expiry::In(std::time::Duration::ZERO)).set(&s("now")), Err(Error::Invalid(_))));
    assert!(matches!(w.at(kept, x).expires(osis::Expiry::At(db.now())).set(&s("now")), Err(Error::Invalid(_))));
    // one batch cannot mix expiries on one group's `group.0` (expiry is per aspect write)
    drop(w);
    let mut w = db.write();
    let g = w.create().unwrap();
    w.group(g).add(osis::Member::Item(db.me())).unwrap();
    assert!(matches!(w.create_expiring_in(db.me(), g, d), Err(Error::Invalid(_))), "a member that stays beside one that goes");
    drop(w);
    let mut w = db.write();
    w.create_expiring_in(db.me(), db.me(), d).unwrap();
    w.create_expiring_in(db.me(), db.me(), d).unwrap();
    assert!(matches!(w.create_expiring_in(db.me(), db.me(), Some(std::time::Duration::from_secs(5))), Err(Error::Invalid(_))));
    assert!(matches!(w.create_in(db.me(), &[db.me()]), Err(Error::Invalid(_))));
    drop(w);
    // the `group.0` field constants are the ones `add` writes
    assert_eq!(db.at(db.me(), core::GROUP).path(p![core::group::ITEMS]).get::<BTreeSet<osis::Tid>>().unwrap(), Some(items(&db)));
}

// spec/commits.md §2 (`created.0`); notes/api.md Reads (`owner_of`, `created`, `now`): the owner fixed at creation, the creating
// commit with its time and receipt, the corrected clock.
#[test]
fn owner_created_now_api_reads() {
    let c = clock();
    let db = Osis::create(cfg(1, MemStore::new(), &c)).unwrap().0;
    assert_eq!(db.now(), osis::WallMs(T0));
    c.advance(5);
    assert_eq!(db.now(), osis::WallMs(T0 + 5));
    let mut w = db.write();
    let t = w.create_durable(db.me()).unwrap();
    let done = w.commit().unwrap().unwrap();
    assert_eq!(db.owner_of(t).unwrap(), Some(db.me()));
    let ci = db.created(t).unwrap().unwrap();
    assert_eq!((ci.commit, ci.ts, ci.node, ci.actor, ci.received), (done.id.commit(), done.ts, db.node(), db.me(), osis::WallMs(T0 + 5)));
    assert_eq!(ci.shown(), osis::WallMs(T0 + 5));
    c.advance(5);
    db.commit_set(t, ak("t:x.0"), &s("later")).unwrap();
    assert_eq!(db.created(t).unwrap().unwrap(), ci, "the creation, not the newest commit");
    let other = common::db(2);
    assert_eq!(db.owner_of(other.me()).unwrap(), None);
    assert_eq!(db.created(other.me()).unwrap(), None);
}

// notes/api.md Reads (`changed`): a thing's last content change, shown at `min(ts, received)`:
// the creation until content changes; placement is no change of the item nor of the group's
// content; a device whose clock runs ahead dates its change at its receipt here, and the
// latest shown change wins over one with a higher `ts`; a delete is a change; an ephemeral
// thing reports its creation.
// spec: none (API surface, notes/api.md)
#[test]
fn changed_content_only_api_reads() {
    let (ca, cb) = (clock(), clock());
    let a = Osis::create(cfg(1, MemStore::new(), &ca)).unwrap().0;
    let j = Osis::pair(cfg(2, MemStore::new(), &cb), &a.pair_offer().unwrap()).unwrap();
    let (_, reply) = a.pair_accept(j.request()).unwrap();
    let b = j.finish(&reply).unwrap();
    let mut w = a.write();
    let t = w.create_durable(a.me()).unwrap();
    w.group(a.me()).add(osis::Member::Item(t)).unwrap();
    w.commit().unwrap();
    assert_eq!(a.changed(t).unwrap(), a.created(t).unwrap());
    ca.advance(10);
    a.commit_set(t, ak("t:x.0"), &s("1")).unwrap();
    let ch = a.changed(t).unwrap().unwrap();
    assert_eq!((ch.commit, ch.shown()), (Some(newest(&a, t)), osis::WallMs(T0 + 10)));
    assert_ne!(a.created(t).unwrap(), Some(ch));
    // placement: neither the item's nor the group's content
    let home = a.changed(a.me()).unwrap();
    ca.advance(10);
    let mut w = a.write();
    let g = w.create_durable(a.me()).unwrap();
    w.commit().unwrap();
    let mut w = a.write();
    w.group(g).add(osis::Member::Item(t)).unwrap();
    w.group(a.me()).remove(osis::Member::Item(t)).unwrap();
    w.commit().unwrap();
    assert_eq!((a.changed(t).unwrap(), a.changed(a.me()).unwrap()), (Some(ch), home));
    // b's clock runs 30 min ahead (within MAX_DRIFT): its change shows at its receipt here
    deliver(&a, &b);
    cb.advance(30 * 60_000);
    b.commit_set(t, ak("t:x.0"), &s("2")).unwrap();
    deliver(&b, &a);
    let ch = a.changed(t).unwrap().unwrap();
    assert_eq!((ch.node, ch.ts.wall_ms(), ch.shown()), (b.node(), osis::WallMs(T0 + 30 * 60_000), osis::WallMs(T0 + 20)));
    // a's next change: its ts follows b's (the clock rule), shown latest at its receipt
    ca.advance(10);
    a.commit_set(t, ak("t:y.0"), &s("3")).unwrap();
    let ch = a.changed(t).unwrap().unwrap();
    assert_eq!((ch.node, ch.shown()), (a.node(), osis::WallMs(T0 + 30)));
    ca.advance(10);
    let mut w = a.write();
    w.delete(t).unwrap();
    w.commit().unwrap();
    assert!(!a.knows(t).unwrap());
    assert_eq!(a.changed(t).unwrap().unwrap().shown(), osis::WallMs(T0 + 40), "a delete is a change");
    let mut w = a.write();
    let e = w.create().unwrap();
    w.at(e, ak("t:x.0~")).set(&s("draft")).unwrap();
    w.commit().unwrap();
    assert!(a.created(e).unwrap().unwrap().commit.is_none());
    assert_eq!(a.changed(e).unwrap(), a.created(e).unwrap());
}

/// The newest held commit on `t` here.
fn newest(db: &Osis, t: osis::Tid) -> osis::CommitId {
    db.commits(&osis::CommitQuery::new().scope(osis::Scope::Thing(t)).limit(1)).unwrap()[0].commit.id.commit().unwrap()
}

// spec/crdt.md §5.6 (a path op into a key with no live entry creates it; concurrent creations
// read as their join), notes/api.md Writes (path ops): two devices of one person each add to a
// set under an absent map key; both elements survive the merge.
#[test]
fn path_op_into_absent_key_spec_crdt_5_6() {
    let c = clock();
    let a = Osis::create(cfg(1, MemStore::new(), &c)).unwrap().0;
    let j = Osis::pair(cfg(2, MemStore::new(), &c), &a.pair_offer().unwrap()).unwrap();
    let (_, reply) = a.pair_accept(j.request()).unwrap();
    let b = j.finish(&reply).unwrap();
    let r = ak("t:reactions.0");
    let mut w = a.write();
    let t = w.create_durable(a.me()).unwrap();
    w.commit().unwrap();
    deliver(&a, &b);
    let mut w = a.write();
    w.at(t, r.clone()).path(p!["m1"]).add(&s("x")).unwrap();
    w.commit().unwrap();
    let mut w = b.write();
    w.at(t, r.clone()).path(p!["m1"]).add(&s("y")).unwrap();
    w.commit().unwrap();
    deliver(&a, &b);
    deliver(&b, &a);
    let want = Value::Map(osis_base::ValueMap::from([(s("m1"), Value::Set(osis_base::ValueSet::from([s("x"), s("y")])))]));
    assert_eq!(a.at(t, r.clone()).get().unwrap(), Some(want.clone()));
    assert_eq!(b.at(t, r).get().unwrap(), Some(want));
}

// spec/commits.md §2 (`created.0` is carried by the first commit and by covering snapshots),
// notes/api.md Reads (`created`): a later compaction snapshot does not replace the creating
// commit; a device holding the snapshot without that commit reports none.
#[test]
fn created_not_a_snapshot_spec_commits_2() {
    let c = clock();
    let a = Osis::create(cfg(1, MemStore::new(), &c)).unwrap().0;
    let j = Osis::pair(cfg(2, MemStore::new(), &c), &a.pair_offer().unwrap()).unwrap();
    let (_, reply) = a.pair_accept(j.request()).unwrap();
    let b = j.finish(&reply).unwrap();
    let mut w = a.write();
    let t = w.create().unwrap();
    w.at(t, ak("t:x.0")).set(&s("v")).unwrap();
    let done = w.commit().unwrap().unwrap();
    c.advance(60_000);
    let snap = a.engine(|e| e.snapshot(&t, &ak("t:x.0"))).unwrap().unwrap();
    assert_eq!(a.created(t).unwrap().unwrap().commit, Some(done.id.commit().unwrap()));
    let pks = a.engine(|e| e.commit_ids().iter().filter(|id| **id != done.id.commit().unwrap()).filter_map(|id| e.package(id).unwrap()).collect::<Vec<_>>());
    for pk in pks {
        b.engine(|e| e.ingest(&pk.bytes, pk.blobs.clone()).unwrap());
    }
    assert!(b.engine(|e| e.header(&done.id.commit().unwrap())).is_none());
    let _ = snap;
    assert_eq!(b.created(t).unwrap(), None);
}

// notes/api.md Handle: hosts with no runtime would never sync and nothing would say so: refused
// before anything is written. No hosts stays local, and a runtime takes them.
// spec: none (API surface, notes/api.md)
#[test]
fn hosts_without_a_runtime_are_refused() {
    let host = osis::HostAddr::new("mem://nobody", [7; 32]);
    let mut c = osis::Config::memory();
    c.hosts = vec![host.clone()];
    let r = Osis::create(c.clone());
    assert!(matches!(&r, Err(Error::Invalid(m)) if m.contains("runtime")), "{:?}", r.map(|_| ()));
    assert!(matches!(Osis::open(c.clone()), Err(Error::Invalid(_))));
    let card_free = Osis::create(osis::Config::memory()).unwrap();
    assert!(card_free.1.is_none());
    c.runtime = osis::Runtime::Manual(osis::internals::ManualNet::new());
    assert!(Osis::create(c).is_ok());
}

// notes/api.md Handle: relays need a transport to use them: a build without one says so.
// spec: none (API surface, notes/api.md)
#[test]
fn relays_without_iroh_are_refused() {
    let mut c = osis::Config::memory();
    c.relays = vec!["https://relay.example.org".into()];
    let r = Osis::create(c);
    assert_eq!(r.is_err(), !cfg!(feature = "iroh"));
}

// notes/api.md Sync configuration: `sync` of a group that has a label never moves it silently: its
// hosts again, or none named, do nothing; other hosts are refused.
// spec: none (API surface, notes/api.md)
#[test]
fn sync_refuses_other_hosts() {
    let db = db(1);
    let (a, b) = (osis::HostAddr::new("mem://a", [1; 32]), osis::HostAddr::new("mem://b", [2; 32]));
    let mut w = db.write();
    let g = w.create().unwrap();
    w.commit().unwrap();
    db.sync(g, std::slice::from_ref(&a)).unwrap();
    db.sync(g, std::slice::from_ref(&a)).unwrap();
    db.sync(g, &[]).unwrap();
    assert!(matches!(db.sync(g, std::slice::from_ref(&b)), Err(Error::Invalid(_))));
    assert!(matches!(db.sync(g, &[a, b]), Err(Error::Invalid(_))));
}

// notes/api.md Reading: `knows` is about content: a thing created and made durable with none reads
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
    assert_eq!(db.created(t).unwrap().map(|c| c.commit.is_some()), Some(true), "durable");
    assert!(!db.knows(t).unwrap(), "no content yet");
    db.commit_set(t, k.clone(), &Value::Int(1)).unwrap();
    assert!(db.knows(t).unwrap());
    let mut w = db.write();
    w.delete(t).unwrap();
    w.commit().unwrap();
    assert!(!db.knows(t).unwrap());
    db.commit_set(t, k, &Value::Int(2)).unwrap();
    assert!(db.knows(t).unwrap());
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
    w.at(t, k.clone()).set(&Value::Int(1)).unwrap();
    w.commit().unwrap();
    let mut w = db.write();
    w.at(t, k.clone()).set(&Value::Int(2)).unwrap();
    let last = w.commit().unwrap().unwrap().id;
    let mut w = db.write();
    w.at(t, k.clone()).purge(osis::Purge::Change(last)).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, k.clone()).get().unwrap(), None);
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
        if d.kind == osis::DiagnosticKind::NotSynced {
            let _ = tx.send(d.tids.clone());
        }
    }).unwrap().detach();
    let group = |w: &mut osis::Write<'_>| {
        w.create().unwrap()
    };
    let synced = db.batch(|w| Ok(group(w))).unwrap();
    db.sync(synced, &[osis::HostAddr::new("mem://a", [1; 32])]).unwrap();
    let mut w = db.write();
    let (mid, low, plain, tag, far, dual) = (group(&mut w), group(&mut w), group(&mut w), group(&mut w), group(&mut w), group(&mut w));
    w.group(synced).add(osis::Member::Subgroup(mid)).unwrap();
    w.group(mid).add(osis::Member::Subgroup(low)).unwrap();
    w.group(plain).add(osis::Member::Subgroup(far)).unwrap();
    w.group(synced).add(osis::Member::Subgroup(tag)).unwrap();
    // `dual` is an item too: its own aspects keep syncing, its items do not
    w.group(synced).add(osis::Member::Subgroup(dual)).unwrap();
    w.group(synced).add(osis::Member::Item(dual)).unwrap();
    let (below, never, in_tag, also_synced, in_dual) = (w.create().unwrap(), w.create().unwrap(), w.create().unwrap(), w.create_owned_by(synced).unwrap(), w.create().unwrap());
    for t in [below, never, in_tag, also_synced, in_dual] {
        w.at(t, k.clone()).set(&Value::Int(1)).unwrap();
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
        if d.kind == osis::DiagnosticKind::NotSynced {
            let _ = tx.send(d.tids.clone());
        }
    }).unwrap().detach();
    let mut w = db.write();
    let g = w.create().unwrap();
    let synced = g;
    w.commit().unwrap();
    db.sync(synced, &[osis::HostAddr::new("mem://a", [1; 32])]).unwrap();
    let mut w = db.write();
    let sub = w.create().unwrap();
    w.group(synced).add(osis::Member::Subgroup(sub)).unwrap();
    let (stranded, kept) = (w.create().unwrap(), w.create_owned_by(synced).unwrap());
    for t in [stranded, kept] {
        w.at(t, k.clone()).set(&Value::Int(1)).unwrap();
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
    let t = db.batch(|w| {
        let t = w.create()?;
        w.at(t, k.clone()).path(p![]).set(&Value::Int(1))?;
        Ok(t)
    }).unwrap();
    assert_eq!(db.at(t, k.clone()).get().unwrap(), Some(Value::Int(1)));
    assert!(commit_with(&db, |w| w.at(t, k.clone()).path(p![]).overwrite(&Value::Int(1))).also.is_empty(), "an overwrite of an equal value writes");
    let mut w = db.write();
    w.at(t, k.clone()).path(p![]).set(&Value::Int(1)).unwrap();
    assert_eq!(w.commit().unwrap(), None, "a set of an equal value does not");
    commit_with(&db, |w| w.at(t, k.clone()).path(p![]).set_stream(&b"bytes"[..]));
    assert_eq!(db.at(t, k.clone()).get().unwrap(), Some(Value::Bytes(b"bytes".to_vec())));
    commit_with(&db, |w| w.at(t, k.clone()).path(p![]).remove());
    assert_eq!(db.at(t, k.clone()).get().unwrap(), None);
    let mut w = db.write();
    w.at(t, k.clone()).path(p!["a"]).set(&Value::Int(1)).unwrap();
    w.at(t, l.clone()).path(p![]).add(&Value::Int(1)).unwrap();
    w.at(t, l.clone()).path(p![]).add(&Value::Int(2)).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, k).path(p!["a"]).get::<Value>().unwrap(), Some(Value::Int(1)));
    let mut w = db.write();
    w.at(t, l.clone()).path(p![Value::Int(1)]).remove().unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, l).get().unwrap(), Some(Value::Set([Value::Int(2)].into_iter().collect())));
}

// spec: none (client surface: notes/api.md Reads). `members` lists a group's members as `groups_of` sees them: durable
// and ephemeral placements alike; a thing that is no group has none
#[test]
fn members_list_a_groups_members() {
    let db = db(1);
    let mut w = db.write();
    let g = w.create().unwrap();
    let (kept, draft, sub) = (w.create().unwrap(), w.create().unwrap(), w.create().unwrap());
    w.at(kept, ak("t:x.0")).set(&Value::Int(1)).unwrap();
    w.at(g, ak("t:x.0")).set(&Value::Int(1)).unwrap();
    w.group(g).add(osis::Member::Item(kept)).unwrap();
    w.group(g).add(osis::Member::Item(draft)).unwrap();
    w.group(g).add(osis::Member::Subgroup(sub)).unwrap();
    w.commit().unwrap();
    let mut want = vec![kept, draft];
    want.sort();
    assert_eq!(db.items(g).unwrap(), want);
    assert_eq!(db.subgroups(g).unwrap(), vec![sub]);
    assert!(db.groups_of(draft).unwrap().item_of.contains(&g), "the same answer from the other side");
    assert_eq!(db.items(kept).unwrap(), Vec::<osis::Tid>::new());
}

// spec/data-model.md §8: any thing becomes a group with its first member, item or subgroup, added
// in a later batch than its creation or in the same; an ephemeral one stays so
#[test]
fn a_first_member_makes_a_group() {
    let db = db(1);
    let (plain, other, a, b) = db
        .batch(|w| {
            let v = [w.create_durable(db.me())?, w.create_durable(db.me())?, w.create_durable(db.me())?, w.create_durable(db.me())?];
            Ok((v[0], v[1], v[2], v[3]))
        })
        .unwrap();
    assert_eq!(db.members(plain).unwrap(), vec![]);
    assert_eq!(db.at(plain, core::GROUP).get().unwrap(), None, "no group yet");
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
    assert!(db.members(other).unwrap().is_empty() && db.at(other, core::GROUP).get().unwrap().is_some());
    // the acting actor's, whoever the batch acts as
    let mut w = db.write();
    let group_actor = w.create_durable(db.me()).unwrap();
    w.commit().unwrap();
    let mut w = db.write();
    w.act_as(group_actor);
    let t = w.create().unwrap();
    w.at(t, ak("t:x.0")).set(&Value::Int(1)).unwrap();
    w.commit().unwrap();
    assert_eq!(db.owner_of(t).unwrap(), Some(group_actor));
    // a new thing in the batch, and a member that stays in memory: nothing durable
    let before = db.engine(|e| e.commit_ids().len());
    let (g, e) = db.batch(|w| {
        let (g, e) = (w.create()?, w.create()?);
        w.group(g).add(osis::Member::Item(e))?;
        Ok((g, e))
    }).unwrap();
    assert_eq!(db.engine(|e| e.commit_ids().len()), before);
    assert_eq!(db.members(g).unwrap(), vec![osis::Member::Item(e)]);
    // a durable group's first member, still in memory: nothing durable either
    let durable = made(&db);
    let before = db.engine(|e| e.commit_ids().len());
    let e = db.batch(|w| {
        let e = w.create()?;
        w.group(durable).add(osis::Member::Item(e))?;
        Ok(e)
    }).unwrap();
    assert_eq!(db.engine(|e| e.commit_ids().len()), before);
    assert_eq!(db.members(durable).unwrap(), vec![osis::Member::Item(e)]);
}

/// A durable thing of `db`'s.
fn made(db: &Osis) -> osis::Tid {
    db.batch(|w| w.create_durable(db.me())).unwrap()
}

// spec/data-model.md §8: two devices each adding what is to them a first member both keep theirs, whichever arrives first
#[test]
fn first_members_on_two_devices_both_stay() {
    let (a, b, _) = paired();
    let (g, x, y) = (made(&a), made(&a), made(&a));
    deliver(&a, &b);
    a.batch(|w| w.group(g).add(osis::Member::Item(x))).unwrap();
    b.batch(|w| w.group(g).add(osis::Member::Item(y))).unwrap();
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
fn a_member_arriving_during_a_batch_stays() {
    let (a, b, _) = paired();
    let (g, x, y) = (made(&a), made(&a), made(&a));
    deliver(&a, &b);
    a.batch(|w| w.group(g).add(osis::Member::Item(x))).unwrap();
    let mut w = b.write();
    w.group(g).add(osis::Member::Item(y)).unwrap();
    deliver(&a, &b);
    w.commit().unwrap();
    deliver(&b, &a);
    assert!(b.members(g).unwrap().contains(&osis::Member::Item(x)));
    assert!(a.members(g).unwrap().contains(&osis::Member::Item(x)), "the loss would spread");
}

// spec/data-model.md §8: a member added after a delete of the group counts, in one batch or from another device
#[test]
fn a_member_added_after_a_delete_stays() {
    let (a, b, c) = paired();
    let (g, x, y) = (made(&a), made(&a), made(&a));
    a.batch(|w| w.group(g).add(osis::Member::Item(x))).unwrap();
    a.batch(|w| {
        w.delete(g)?;
        w.group(g).add(osis::Member::Item(y))
    })
    .unwrap();
    assert_eq!(a.members(g).unwrap(), vec![osis::Member::Item(y)], "the same batch");
    let h = made(&a);
    a.batch(|w| w.group(h).add(osis::Member::Item(x))).unwrap();
    deliver(&a, &b);
    a.batch(|w| w.delete(h)).unwrap();
    c.advance(1000);
    b.batch(|w| w.group(h).add(osis::Member::Item(y))).unwrap();
    deliver(&a, &b);
    deliver(&b, &a);
    assert_eq!(a.members(h).unwrap(), vec![osis::Member::Item(y)], "a later add on another device");
    assert_eq!(b.members(h).unwrap(), vec![osis::Member::Item(y)]);
}

// spec/commits.md §6: what an expiring first member wrote leaves a later lasting member alone, in either field
#[test]
fn a_lasting_member_outlives_an_expiring_first() {
    let c = clock();
    let db = Osis::create(cfg(1, MemStore::new(), &c)).unwrap().0;
    let (g, x, s, y) = (made(&db), made(&db), made(&db), made(&db));
    let minute = osis::Expiry::In(std::time::Duration::from_secs(60));
    db.batch(|w| {
        w.group(g).expires(minute).add(osis::Member::Item(x))?;
        w.group(g).expires(minute).add(osis::Member::Subgroup(s))
    })
    .unwrap();
    db.batch(|w| w.group(g).add(osis::Member::Item(y))).unwrap();
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
    b.batch(|w| w.group(g).add(osis::Member::Item(y))).unwrap();
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
    a.batch(|w| w.group(only).add(osis::Member::Item(y))).unwrap();
    assert_eq!(a.members(only).unwrap(), vec![osis::Member::Item(y)], "and it can be one again");
}

// spec/commits.md §6, notes/api.md Writes: a subgroup expires as an item does; a removal in an expiring batch is the disagreement it always was
#[test]
fn membership_expires_item_or_subgroup_spec_commits_6() {
    let c = clock();
    let db = Osis::create(cfg(1, MemStore::new(), &c)).unwrap().0;
    let minute = osis::Expiry::In(std::time::Duration::from_secs(60));
    let mut w = db.write();
    let (g, t, s, kept) = (w.create_durable(db.me()).unwrap(), w.create_durable(db.me()).unwrap(), w.create_durable(db.me()).unwrap(), w.create_durable(db.me()).unwrap());
    w.commit().unwrap();
    let mut w = db.write();
    w.group(g).expires(minute).add(osis::Member::Item(t)).unwrap();
    w.group(g).expires(osis::Expiry::In(std::time::Duration::from_secs(60))).add(osis::Member::Subgroup(s)).unwrap();
    assert!(matches!(w.group(g).add(osis::Member::Item(kept)), Err(Error::Invalid(_))), "the batch's write of the group has one expiry");
    assert!(matches!(w.group(g).remove(osis::Member::Item(kept)), Err(Error::Invalid(_))), "nor a removal");
    assert!(matches!(w.group(g).expires(osis::Expiry::In(std::time::Duration::from_secs(5))).add(osis::Member::Item(kept)), Err(Error::Invalid(_))));
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

// spec/data-model.md §8: a group and its member, made in memory in one batch, keep as either is written: the member's first durable
// write keeps both, in one batch with the add or a later one; the group's keeps it alone, the member still in memory there
#[test]
fn a_group_and_member_of_one_batch_keep_by_what_is_written() {
    let db = db(1);
    let x = ak("t:x.0");
    let kept = |t: osis::Tid| db.created(t).unwrap().unwrap().commit.is_some();
    let new = |write_member: bool| {
        db.batch(|w| {
            let (g, m) = (w.create()?, w.create()?);
            w.group(g).add(osis::Member::Item(m))?;
            if write_member {
                w.at(m, x.clone()).set(&Value::Int(1))?;
            }
            Ok((g, m))
        })
        .unwrap()
    };
    let check = |g, m, what: &str| {
        assert!(kept(g) && kept(m), "{what}");
        assert_eq!(db.at(g, core::GROUP).get().unwrap().unwrap().items, [m].into(), "{what}: durably");
        assert_eq!(db.groups_of(m).unwrap().item_of, vec![g], "{what}: one membership");
        db.engine(|e| {
            assert!(e.closure(&g).contains(&m), "{what}: sync follows");
        });
    };
    let (g, m) = new(true);
    check(g, m, "the same batch");
    let (g, m) = new(false);
    assert!(!kept(g) && !kept(m));
    db.batch(|w| w.at(m, x.clone()).set(&Value::Int(1))).unwrap();
    check(g, m, "the member later");
    let (g, m) = new(false);
    db.batch(|w| w.at(g, x.clone()).set(&Value::Int(1))).unwrap();
    assert!(kept(g) && !kept(m), "the group alone");
    assert_eq!(db.members(g).unwrap(), vec![osis::Member::Item(m)]);
    assert!(db.engine(|e| e.durable_groups_of(&m).is_empty()), "only in memory");
    db.batch(|w| w.at(m, x.clone()).set(&Value::Int(1))).unwrap();
    check(g, m, "then the member");
}

// spec: none (client surface: notes/api.md Writes). One splice for a list and for text: replaces a range, an empty range inserts, no items delete
#[test]
fn splice_lists_and_text() {
    let db = db(1);
    let mut w = db.write();
    let t = w.create().unwrap();
    w.at(t, notes::TASKS).set(&vec![task("a"), task("b"), task("c")]).unwrap();
    w.at(t, notes::BODY).set(&"hello world".to_string()).unwrap();
    w.commit().unwrap();
    let titles = || db.at(t, notes::TASKS).get().unwrap().unwrap().into_iter().map(|x| x.title).collect::<Vec<_>>();
    commit_with(&db, |w| w.at(t, notes::TASKS).path(p![]).splice(1..2, &[task("x"), task("y")]));
    assert_eq!(titles(), ["a", "x", "y", "c"]);
    commit_with(&db, |w| w.at(t, notes::TASKS).path(p![]).splice(0..0, &vec![task("z")]));
    assert_eq!(titles(), ["z", "a", "x", "y", "c"]);
    commit_with(&db, |w| w.at(t, notes::TASKS).path(p![]).splice(0..2, ()));
    assert_eq!(titles(), ["x", "y", "c"]);
    let mut w = db.write();
    w.at(t, notes::TASKS).path(p![]).splice(1..1, ()).unwrap();
    assert_eq!(w.commit().unwrap(), None, "nothing to do writes nothing");
    let mut w = db.write();
    assert!(matches!(w.at(t, notes::TASKS).path(p![]).splice(1..1, "text"), Err(Error::Invalid(_))), "a list takes items");
    assert!(matches!(w.at(t, notes::TASKS).path(p![]).splice(1..2, ""), Err(Error::Invalid(_))), "even none, as a string");
    assert!(matches!(w.at(t, notes::TASKS).path(p![]).splice(1..1, &[1_i64]), Err(Error::Type { .. })), "of its type");
    #[allow(clippy::reversed_empty_ranges)]
    let backward = 2..1;
    assert!(matches!(w.at(t, notes::TASKS).path(p![]).splice(backward, ()), Err(Error::Invalid(_))));
    drop(w);
    commit_with(&db, |w| w.at(t, notes::BODY).path(p![]).splice(0..5, "goodbye"));
    assert_eq!(db.at(t, notes::BODY).get().unwrap().as_deref(), Some("goodbye world"));
}

// spec: none (client surface: notes/api.md Text editing sessions). Positions are addressed one way: a session at a path as at the aspect
#[test]
fn edit_text_by_position() {
    let db = db(1);
    let k = ak("t:m.0");
    let mut w = db.write();
    let t = w.create().unwrap();
    w.at(t, k.clone()).path(p!["a"]).set(&"one".to_string()).unwrap();
    w.commit().unwrap();
    let ed = db.at(t, k.clone()).path(p!["a"]).edit_text().unwrap();
    assert_eq!(ed.text(), "one");
    ed.splice(3..3, "!").unwrap();
    ed.commit().unwrap();
    assert_eq!(db.at(t, k.clone()).path(p!["a"]).get::<String>().unwrap().as_deref(), Some("one!"));
    assert!(matches!(db.at(t, k).path(osis::p![]).edit_text(), Err(Error::Invalid(_))), "the whole aspect is no string");
}
