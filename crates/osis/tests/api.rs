//! Handle, keys, reads, the `Write` batch, rights, errors (notes/api.md Handle, Keys, Reads,
//! Writes, Errors, Footguns closed).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;
use common::*;
use osis::schema::core_types::Group;
use osis::{Error, MemStore, Osis, Place, Role, Value, core, p};
use std::collections::{BTreeMap, BTreeSet};

#[allow(clippy::all, dead_code)]
mod notes {
    use osis::schema as osis_schema;
    include!("../../osis-schema/tests/gen/notes.rs");
}
use notes::{Task, task};

fn s(x: &str) -> Value {
    Value::Str(x.into())
}

fn task(title: &str) -> Task {
    Task { title: title.into(), done: false, tags: BTreeSet::new(), priority: None, due: None, status: None, weight: osis::schema::osis_core::Float::new(1.0) }
}

// notes/api.md Handle and lifecycle: a new database has a node, a person actor and its home
// group; reopening the store gives the same identity.
#[test]
fn create_and_reopen_spec_api_handle() {
    let store = MemStore::new();
    let c = clock();
    let (node, me, home) = {
        let db = Osis::create(cfg(1, store.clone(), &c)).unwrap();
        assert_ne!(db.me(), db.node());
        assert_eq!(db.get(db.home(), core::GROUP).unwrap(), Some(Group::default()));
        assert_eq!(db.role_on(db.me()), Some(Role::Admin));
        (db.node(), db.me(), db.home())
    };
    fn send_sync<T: Send + Sync>() {}
    send_sync::<Osis>();
    send_sync::<osis::Watch<String>>();
    send_sync::<osis::Subscription>();
    let db = Osis::open(cfg(2, store, &c)).unwrap();
    assert_eq!((db.node(), db.me(), db.home()), (node, me, home));
    // an empty store is not a database
    assert!(Osis::open(cfg(3, MemStore::new(), &c)).is_err());
}

// spec/versioning.md §5, notes/api.md Keys: typed keys from codegen read and write typed
// values; per-path typed reads; a typed read of mistyped data fails with the path while the
// untyped read works.
#[test]
fn typed_keys_and_paths_spec_versioning_5() {
    let db = db(1);
    let mut w = db.write();
    let n = w.create(db.me(), Place::In(db.home())).unwrap();
    w.at(n, notes::TITLE).set(&"Groceries".to_string()).unwrap();
    w.at(n, notes::TASKS).set(&vec![task("milk"), task("eggs")]).unwrap();
    w.commit().unwrap();
    assert_eq!(db.get(n, notes::TITLE).unwrap().as_deref(), Some("Groceries"));
    assert_eq!(db.get(n, notes::TASKS).unwrap().unwrap()[1].title, "eggs");
    let at = db.at(n, notes::TASKS);
    assert_eq!(at.path(p![1, task::TITLE]).get::<String>().unwrap().as_deref(), Some("eggs"));
    assert_eq!(at.path(p![5, task::TITLE]).get_value().unwrap(), None);
    // path op on a typed list element
    db.write_with(|w| w.at(n, notes::TASKS).path(p![0, task::DONE]).set(&true)).unwrap();
    assert!(db.get(n, notes::TASKS).unwrap().unwrap()[0].done);
    // mistyped data: untyped write of an int under a string AK
    db.write_with(|w| w.at(n, ak("/note/title")).set(&Value::Int(3))).unwrap();
    assert!(matches!(db.get(n, notes::TITLE), Err(Error::Type { .. })));
    assert_eq!(db.get(n, ak("/note/title")).unwrap(), Some(Value::Int(3)));
    // a typed write is validated against the writer's schema
    let mut w = db.write();
    assert!(matches!(w.at(n, notes::TASKS).path(p![0, task::DONE]).set(&s("no")), Err(Error::Type { .. })));
}

// notes/api.md Keys: a schema registered at run time types `Key` reads (reader defaults) and
// validates writes; unknown AKs stay untyped.
#[test]
fn registered_schema_key_spec_api_keys() {
    let db = db(1);
    db.register_schema_source("notes.osis", notes::SCHEMA.source()).unwrap();
    assert!(db.register_schema_source("bad.osis", "schema nonsense").is_err());
    let title = db.key("/note/title").unwrap();
    assert!(title.schema().is_some());
    assert!(db.key("/other/x").unwrap().schema().is_none());
    let mut w = db.write();
    let n = w.create(db.me(), Place::Unsynced).unwrap();
    assert!(matches!(w.at(n, title.clone()).set(&Value::Int(1)), Err(Error::Type { .. })));
    w.at(n, title.clone()).set(&s("x")).unwrap();
    // a task without `weight` reads with the declared default
    let mut t = BTreeMap::new();
    t.insert(Value::Int(1), s("a"));
    t.insert(Value::Int(2), Value::Bool(false));
    t.insert(Value::Int(3), Value::Set(BTreeSet::new()));
    w.at(n, ak("/note/tasks")).set(&Value::List(vec![Value::Map(t)])).unwrap();
    w.commit().unwrap();
    let tasks = db.key("/note/tasks").unwrap();
    let v = db.at(n, tasks).path(p![0, task::WEIGHT]).get_value().unwrap();
    assert_eq!(v, Some(Value::float(1.0)));
}

// notes/api.md Reads: absent aspects and unknown things read as None, never as errors.
#[test]
fn absent_reads_none_spec_api_reads() {
    let db = db(1);
    let other = db_other_thing();
    assert_eq!(db.get(other, ak("/a/b")).unwrap(), None);
    assert_eq!(db.get(db.me(), ak("/a/b")).unwrap(), None);
    assert!(!db.knows(other));
    assert_eq!(db.role_on(other), None);
}

fn db_other_thing() -> osis::Tid {
    let o = db(9);
    o.me()
}

fn titles(db: &Osis, t: osis::Tid) -> Vec<String> {
    db.get(t, notes::TASKS).unwrap().unwrap().into_iter().map(|x| x.title).collect()
}

// notes/api.md Writes: whole-value ops and every path op.
#[test]
fn write_ops_spec_api_writes() {
    let db = db(1);
    let mut w = db.write();
    let t = w.create(db.me(), Place::Unsynced).unwrap();
    let (m, st, c) = (ak("/t/map"), ak("/t/set"), ak("/t/reg"));
    w.at(t, m.clone()).path(p![]).put(&"a".to_string(), &1i64).unwrap();
    w.at(t, m.clone()).path(p![]).put(&"b".to_string(), &2i64).unwrap();
    w.at(t, st.clone()).path(p![]).add(&"x".to_string()).unwrap();
    w.at(t, st.clone()).path(p![]).add(&"y".to_string()).unwrap();
    w.at(t, notes::TASKS).set(&vec![task("a"), task("b"), task("c")]).unwrap();
    w.at(t, c.clone()).set(&s("one")).unwrap();
    w.commit().unwrap();
    db.write_with(|w| {
        w.at(t, m.clone()).path(p![]).remove_key(&"a".to_string())?;
        w.at(t, m.clone()).path(p!["b"]).set(&5i64)?;
        w.at(t, st.clone()).path(p![]).remove_elem(&"x".to_string())?;
        w.at(t, notes::TASKS).path(p![]).insert(0, &[task("z")])?;
        w.at(t, c.clone()).replace(&s("two"))
    })
    .unwrap();
    assert_eq!(db.get(t, m.clone()).unwrap(), Some(Value::Map(BTreeMap::from([(s("b"), Value::Int(5))]))));
    assert_eq!(db.get(t, st.clone()).unwrap(), Some(Value::Set(BTreeSet::from([s("y")]))));
    assert_eq!(titles(&db, t), ["z", "a", "b", "c"]);
    assert_eq!(db.get(t, c.clone()).unwrap(), Some(s("two")));
    db.write_with(|w| {
        w.at(t, notes::TASKS).path(p![]).delete(0..1)?;
        w.at(t, notes::TASKS).path(p![2]).remove()
    })
    .unwrap();
    db.write_with(|w| w.at(t, notes::TASKS).path(p![]).move_range(0..1, 1)).unwrap();
    assert_eq!(titles(&db, t), ["b", "a"]);
    db.write_with(|w| w.at(t, m.clone()).path(p!["b"]).remove()).unwrap();
    assert_eq!(db.get(t, m.clone()).unwrap(), Some(Value::Map(BTreeMap::new())));
    // counter, max, enum case, text splice through typed keys
    db.write_with(|w| {
        w.at(t, notes::VIEWS).inc(&2i64)?;
        w.at(t, notes::VIEWS).inc(&3i64)?;
        w.at(t, notes::BODY).set(&"hello world".to_string())
    })
    .unwrap();
    assert_eq!(db.get(t, notes::VIEWS).unwrap(), Some(5));
    db.write_with(|w| w.at(t, notes::BODY).path(p![]).splice(0..5, "goodbye")).unwrap();
    assert_eq!(db.get(t, notes::BODY).unwrap().as_deref(), Some("goodbye world"));
    db.write_with(|w| w.at(t, notes::TASKS).set(&vec![task("a")])).unwrap();
    db.write_with(|w| w.at(t, notes::TASKS).path(p![0, task::PRIORITY]).set_case(osis::CaseId(1), Some(Value::Enum(2, None)))).unwrap();
    assert_eq!(db.get(t, notes::TASKS).unwrap().unwrap()[0].priority, Some(notes::Priority::High));
    // max: observe keeps the largest contribution
    db.register_schema_source("t.osis", "schema 0x0123456789abcdef0123456789abcdef;\nrevision 1;\naspect /t/max: max<int>;\n").unwrap();
    let mx = db.key("/t/max").unwrap();
    db.write_with(|w| {
        w.at(t, mx.clone()).path(p![]).observe(&7i64)?;
        w.at(t, mx.clone()).path(p![]).observe(&3i64)
    })
    .unwrap();
    assert_eq!(db.get(t, mx).unwrap(), Some(Value::Int(7)));
    // remove the aspect; a field cannot be removed by path
    db.write_with(|w| w.at(t, c.clone()).remove()).unwrap();
    assert_eq!(db.get(t, c).unwrap(), None);
    let mut w = db.write();
    assert!(matches!(w.at(t, notes::TASKS).path(p![0, task::DONE]).remove(), Err(Error::Invalid(_))));
    // a set element is atomic
    assert!(matches!(w.at(t, st).path(osis::Path(vec![osis::Step::Elem(s("y"))])).set(&1i64), Err(Error::Invalid(_))));
}

// notes/api.md Writes, Footguns closed: `edit(base, new)` keeps a change made to another field
// after the app read `base`; `set` of the same edited value writes that field back.
#[test]
fn edit_keeps_concurrent_change_set_clobbers_spec_api_footguns() {
    let db = db(1);
    let k = ak("/t/form");
    let form = |a: &str, b: &str| Value::Map(BTreeMap::from([(Value::Int(0), s(a)), (Value::Int(1), s(b))]));
    let mut w = db.write();
    let t = w.create(db.me(), Place::Unsynced).unwrap();
    w.at(t, k.clone()).set(&form("a", "b")).unwrap();
    w.commit().unwrap();
    let shown = db.get(t, k.clone()).unwrap().unwrap();
    // meanwhile another writer changes field 1
    db.write_with(|w| w.at(t, k.clone()).path(p![Value::Int(1)]).set(&s("B"))).unwrap();
    assert_eq!(db.get(t, k.clone()).unwrap(), Some(form("a", "B")));
    // the user edits field 0 of what they were shown
    let edited = form("A", "b");
    db.write_with(|w| w.at(t, k.clone()).edit(&shown, &edited)).unwrap();
    assert_eq!(db.get(t, k.clone()).unwrap(), Some(form("A", "B")));
    // `set` of the edited value clobbers the concurrent change
    db.write_with(|w| w.at(t, k.clone()).path(p![Value::Int(1)]).set(&s("C"))).unwrap();
    db.write_with(|w| w.at(t, k.clone()).set(&edited)).unwrap();
    assert_eq!(db.get(t, k).unwrap(), Some(form("A", "b")));
}

// notes/api.md Reads, Large values: a value above the materialization bound fails TooLarge
// (chunked or not); a path read of a small position of the same aspect works.
#[test]
fn materialization_bound_spec_data_model_6() {
    let c = clock();
    let mut cf = cfg(1, MemStore::new(), &c);
    cf.materialize_limit = 64 * 1024;
    let db = Osis::create(cf).unwrap();
    let k = ak("/t/doc");
    let big = Value::Bytes(vec![7u8; osis::schema::osis_core::format::CHUNK_THRESHOLD + 1000]);
    let mid = Value::Bytes(vec![1u8; 100 * 1024]);
    let mut w = db.write();
    let t = w.create(db.me(), Place::Unsynced).unwrap();
    w.at(t, k.clone()).set(&Value::Map(BTreeMap::from([(Value::Int(0), big), (Value::Int(1), s("small")), (Value::Int(2), mid)]))).unwrap();
    w.commit().unwrap();
    assert_eq!(db.get(t, k.clone()), Err(Error::TooLarge { limit: 64 * 1024 }));
    assert_eq!(db.at(t, k.clone()).path(p![osis::FieldId(1)]).get::<String>().unwrap().as_deref(), Some("small"));
    assert!(matches!(db.at(t, k.clone()).path(p![osis::FieldId(0)]).get_value(), Err(Error::TooLarge { .. })));
    assert!(matches!(db.at(t, k.clone()).path(p![osis::FieldId(2)]).get_value(), Err(Error::TooLarge { .. })));
}

// spec/data-model.md §6: a chunked large value reads back whole within the bound.
#[test]
fn large_value_round_trip_spec_data_model_6() {
    let db = db(1);
    let k = ak("/t/blob");
    let big = Value::Bytes((0..osis::schema::osis_core::format::CHUNK_THRESHOLD * 2).map(|i| (i % 251) as u8).collect());
    let mut w = db.write();
    let t = w.create(db.me(), Place::Unsynced).unwrap();
    w.at(t, k.clone()).set(&big).unwrap();
    w.commit().unwrap();
    assert_eq!(db.get(t, k).unwrap(), Some(big));
}

// notes/api.md Writes: create with explicit owner and placement; groups; place, unplace,
// subgroups, delete.
#[test]
fn create_place_delete_spec_data_model_8() {
    let db = db(1);
    let mut w = db.write();
    let folder = w.create(db.me(), Place::In(db.home())).unwrap();
    w.make_group(folder).unwrap();
    let a = w.create(db.me(), Place::InAll(vec![folder, db.home()])).unwrap();
    let b = w.create(db.me(), Place::Unsynced).unwrap();
    w.at(a, ak("/t/x")).set(&Value::Int(1)).unwrap();
    w.commit().unwrap();
    assert_eq!(db.groups_of(a).into_iter().collect::<BTreeSet<_>>(), BTreeSet::from([folder, db.home()]));
    assert!(db.groups_of(b).is_empty());
    db.write_with(|w| {
        w.place(b, folder)?;
        w.unplace(a, db.home())
    })
    .unwrap();
    assert_eq!(db.groups_of(a), vec![folder]);
    let sub = db
        .write_with(|w| {
            let s = w.create(db.me(), Place::Unsynced)?;
            w.make_group(s)?;
            w.add_subgroup(folder, s)?;
            w.place(b, s)
        })
        .unwrap();
    assert!(sub.is_some());
    assert!(db.groups_of(b).contains(&folder));
    db.write_with(|w| w.delete(a)).unwrap();
    assert!(db.groups_of(a).is_empty());
    assert_eq!(db.get(a, ak("/t/x")).unwrap(), None);
    assert!(db.knows(a));
    // an unknown group or owner
    let mut w = db.write();
    let stranger = db_other_thing();
    assert_eq!(w.create(stranger, Place::Unsynced), Err(Error::UnknownThing { tid: stranger }));
    assert_eq!(w.create(db.me(), Place::In(stranger)), Err(Error::UnknownThing { tid: stranger }));
}

// spec/permissions.md §1, notes/api.md Writes: rights are checked locally before signing:
// a node without write on a thing gets Permission; an unknown thing UnknownThing; nothing is
// committed.
#[test]
fn local_rights_check_spec_permissions_1() {
    let a = db(1);
    let b = db(2);
    let mut w = a.write();
    let t = w.create(a.me(), Place::Unsynced).unwrap();
    w.at(t, ak("/t/x")).set(&Value::Int(1)).unwrap();
    w.commit().unwrap();
    // b does not know t yet
    let mut w = b.write();
    w.at(t, ak("/t/x")).set(&Value::Int(2)).unwrap();
    assert_eq!(w.commit(), Err(Error::UnknownThing { tid: t }));
    deliver(&a, &b);
    assert_eq!(b.get(t, ak("/t/x")).unwrap(), Some(Value::Int(1)));
    assert_eq!(b.role_on(t), None);
    let before = b.engine(|e| e.commit_ids().len());
    let mut w = b.write();
    w.at(t, ak("/t/x")).set(&Value::Int(2)).unwrap();
    assert_eq!(w.commit(), Err(Error::Permission { tid: t, needs: Role::Write }));
    assert_eq!(b.engine(|e| e.commit_ids().len()), before);
    // creating under someone else's actor
    let mut w = b.write();
    w.create(a.me(), Place::Unsynced).unwrap();
    assert!(matches!(w.commit(), Err(Error::Permission { .. })));
    // signals need write too
    assert!(matches!(b.send_signal(t, &ak("/t/sig"), &Value::Int(1), osis::Target::All), Err(Error::Permission { .. })));
}

// notes/api.md Writes: membership-class and synthetic aspects are not written by ops.
#[test]
fn membership_class_refused_spec_permissions_1() {
    let db = db(1);
    let t = db.me();
    let mut w = db.write();
    assert!(matches!(w.at(t, core::MOVED).set(&t), Err(Error::Invalid(_))));
    assert!(matches!(w.at(t, ak("/members")).remove(), Err(Error::Invalid(_))));
    assert!(matches!(w.at(t, ak("/groups")).remove(), Err(Error::Invalid(_))));
    // /group is ordinary
    w.at(t, core::GROUP).set(&Group::default()).unwrap();
}

// spec/commits.md §6, §5: per-write expiry kills the value at T; retention per write; purge
// drops the history and removes the aspect.
#[test]
fn expiry_retention_purge_spec_commits_5_6() {
    let c = clock();
    let db = Osis::create(cfg(1, MemStore::new(), &c)).unwrap();
    let (k, r) = (ak("/t/msg"), ak("/t/keep"));
    let mut w = db.write();
    let t = w.create(db.me(), Place::Unsynced).unwrap();
    w.at(t, k.clone()).expires_in(std::time::Duration::from_secs(60)).set(&s("hi")).unwrap();
    let ret = osis::Retention { by: osis::schema::PurgeBy::Writer, ..Default::default() };
    w.at(t, r.clone()).retention(ret).set(&s("kept")).unwrap();
    w.commit().unwrap();
    assert_eq!(db.get(t, k.clone()).unwrap(), Some(s("hi")));
    c.advance(61_000);
    db.engine(|e| e.tick()).unwrap();
    assert_eq!(db.get(t, k.clone()).unwrap(), None);
    // expiry in the past is invalid at commit
    let mut w = db.write();
    assert!(matches!(w.at(t, k.clone()).expires_at(osis::WallMs(T0)).set(&s("late")), Err(Error::Invalid(_))));
    drop(w);
    // purge
    db.write_with(|w| w.at(t, r.clone()).purge()).unwrap();
    assert_eq!(db.get(t, r.clone()).unwrap(), None);
}

// notes/api.md Writes: `act_as` changes the header actor; the default is `me()`.
#[test]
fn act_as_spec_commits_1() {
    let db = db(1);
    let mut w = db.write();
    let t = w.create(db.me(), Place::Unsynced).unwrap();
    let c1 = w.commit().unwrap().unwrap();
    let mut w = db.write();
    w.act_as(db.node());
    w.at(t, ak("/t/x")).set(&Value::Int(1)).unwrap();
    let c2 = w.commit().unwrap().unwrap();
    let actor = |c: osis::CommitId| db.engine(|e| e.header(&c).unwrap().actor);
    assert_eq!((actor(c1.commit), actor(c2.commit)), (db.me(), db.node()));
    // an empty write commits nothing
    assert_eq!(db.write().commit().unwrap(), None);
}

// spec/permissions.md §7, notes/api.md Tids and moves: a moved thing reads through its old
// tid; same_thing is the explicit identity check.
#[test]
fn move_and_same_thing_spec_permissions_7() {
    let db = db(1);
    let mut w = db.write();
    let t = w.create(db.me(), Place::Unsynced).unwrap();
    let owner2 = w.create(db.me(), Place::Unsynced).unwrap();
    w.at(t, ak("/t/x")).set(&Value::Int(1)).unwrap();
    w.commit().unwrap();
    let m = db.move_thing(t, owner2, Place::In(db.home())).unwrap();
    assert_ne!(m, t);
    assert!(db.same_thing(t, m));
    assert!(!db.same_thing(t, owner2));
    assert_eq!(db.get(m, ak("/t/x")).unwrap(), Some(Value::Int(1)));
    assert_eq!(db.get(t, ak("/t/x")).unwrap(), Some(Value::Int(1)));
    assert!(db.groups_of(m).contains(&db.home()));
}

// notes/api.md Sharing, Sync: the second-half surface exists and says it is not there yet.
#[test]
fn stubs_unsupported_spec_api_sharing() {
    let db = db(1);
    let me = db.me();
    assert!(matches!(db.grant(me, me, Role::Read, Default::default()), Err(Error::Unsupported(_))));
    assert!(matches!(db.status(), Err(Error::Unsupported(_))));
    assert!(matches!(db.servers(), Err(Error::Unsupported(_))));
    assert!("".parse::<osis::ServerAddr>().is_err());
    assert_eq!("quic://h:1#k".parse::<osis::ServerAddr>().unwrap().to_string(), "quic://h:1#k");
}

// spec/data-model.md §9: `/created` is typed by its exclusivity rule (owner or key), not the
// missing-field rule, so a run-time core key (`Osis::key`, the CLI's) reads it.
#[test]
fn created_reads_through_run_time_key_spec_data_model_9() {
    let db = Osis::create(osis::Config::memory()).unwrap();
    let mut w = db.write();
    let t = w.create(db.me(), Place::Unsynced).unwrap();
    w.commit().unwrap();
    let v = db.get(t, db.key("/created").unwrap()).unwrap().unwrap();
    assert!(matches!(&v, Value::Map(m) if m.get(&Value::Int(0)) == Some(&Value::Tid(db.me()))));
}
