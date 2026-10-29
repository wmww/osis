//! Handle, keys, reads, the `Write` batch, rights, errors (notes/api.md Handle, Keys, Reads,
//! Writes, Errors, Footguns closed).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

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
    let (node, me, home) = {
        let db = Osis::create(cfg(1, store.clone(), &c)).unwrap().0;
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

// spec/versioning.md §5, notes/api.md Keys, Typed reads: typed keys from codegen read and
// write typed values; per-path typed reads; a typed read of mistyped data reads as absent with
// a `Mismatch` diagnostic naming the path, while the untyped read works; one bad element of a
// list fails the whole typed read but not a path read of another element.
#[test]
fn typed_keys_and_paths_spec_versioning_5() {
    let db = db(1);
    let mut w = db.write();
    let n = w.create_in(db.me(), &[db.home()]).unwrap();
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
    let (tx, diags) = std::sync::mpsc::channel();
    let _d = db.on_diagnostic(move |_, d| {
        if d.kind == osis::DiagnosticKind::Mismatch {
            tx.send(d).unwrap();
        }
    });
    db.write_with(|w| w.at(n, ak("/note/title")).set(&Value::Int(3))).unwrap();
    assert_eq!(db.get(n, notes::TITLE).unwrap(), None, "absent, not an error");
    let d = recv(&diags);
    assert_eq!((d.tids, d.detail.as_str()), (vec![n], "/note/title: type error at (root): expected string"));
    assert_eq!(db.get(n, ak("/note/title")).unwrap(), Some(Value::Int(3)));
    // one element of another shape (as a newer revision's enum case would be)
    let Value::List(mut l) = osis::schema::AspectKey::encode(&notes::TASKS, &vec![task("milk"), task("eggs")]) else { panic!() };
    let Some(Value::Map(m)) = l.get_mut(1) else { panic!() };
    m.insert(Value::Int(1), Value::Int(7));
    db.write_with(|w| w.at(n, ak("/note/tasks")).set(&Value::List(l))).unwrap();
    assert_eq!(db.get(n, notes::TASKS).unwrap(), None);
    let at = db.at(n, notes::TASKS);
    assert_eq!(at.path(p![0, task::TITLE]).get::<String>().unwrap().as_deref(), Some("milk"));
    assert_eq!(at.path(p![1, task::TITLE]).get::<String>().unwrap(), None);
    assert_eq!(at.path(p![1]).get_value().unwrap(), None);
    assert_eq!(at.path(p![0]).get::<Task>().unwrap().map(|t| t.title).as_deref(), Some("milk"));
    // a path the schema does not have is the caller's mistake: an error
    assert!(matches!(at.path(osis::Path(vec![osis::Step::Index(0), osis::Step::Field(99)])).get_value(), Err(Error::Type { .. })));
    // a typed write is validated against the writer's schema
    let mut w = db.write();
    let e = w.at(n, notes::TASKS).path(p![0, task::DONE]).set(&s("no")).unwrap_err();
    assert!(matches!(&e, Error::Type { path, .. } if *path == p![0, task::DONE]), "{e}: the path from the aspect's root");
}

// notes/api.md Keys: a schema registered at run time types `Key` reads (reader defaults) and
// validates writes; unknown AKs stay untyped.
// spec: none (API surface, notes/api.md)
#[test]
fn registered_schema_key_spec_api_keys() {
    let db = db(1);
    db.register_schema_source("notes.osis", notes::SCHEMA.source()).unwrap();
    assert!(db.register_schema_source("bad.osis", "schema nonsense").is_err());
    let title = db.key("/note/title").unwrap();
    assert!(title.schema().is_some());
    assert!(db.key("/other/x").unwrap().schema().is_none());
    let mut w = db.write();
    let n = w.create(db.me()).unwrap();
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
// spec: none (API surface, notes/api.md)
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
// spec: none (API surface, notes/api.md)
#[test]
fn write_ops_spec_api_writes() {
    let db = db(1);
    let mut w = db.write();
    let t = w.create(db.me()).unwrap();
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
// spec: none (API surface, notes/api.md)
#[test]
fn edit_keeps_concurrent_change_set_clobbers_spec_api_footguns() {
    let db = db(1);
    let k = ak("/t/form");
    let form = |a: &str, b: &str| Value::Map(BTreeMap::from([(Value::Int(0), s(a)), (Value::Int(1), s(b))]));
    let mut w = db.write();
    let t = w.create(db.me()).unwrap();
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
// spec/data-model.md §6
#[test]
fn materialization_bound_spec_data_model_6() {
    let c = clock();
    let mut cf = cfg(1, MemStore::new(), &c);
    cf.materialize_limit = 64 * 1024;
    let db = Osis::create(cf).unwrap().0;
    let k = ak("/t/doc");
    let big = Value::Bytes(vec![7u8; osis::schema::osis_base::format::CHUNK_THRESHOLD + 1000]);
    let mid = Value::Bytes(vec![1u8; 100 * 1024]);
    let mut w = db.write();
    let t = w.create(db.me()).unwrap();
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
    let big = Value::Bytes((0..osis::schema::osis_base::format::CHUNK_THRESHOLD * 2).map(|i| (i % 251) as u8).collect());
    let mut w = db.write();
    let t = w.create(db.me()).unwrap();
    w.at(t, k.clone()).set(&big).unwrap();
    w.commit().unwrap();
    assert_eq!(db.get(t, k).unwrap(), Some(big));
}

// notes/api.md Writes: create with explicit owner and placement; groups; place, unplace,
// subgroups, delete.
// spec/data-model.md §8
#[test]
fn create_place_delete_spec_data_model_8() {
    let db = db(1);
    let mut w = db.write();
    let folder = w.create_in(db.me(), &[db.home()]).unwrap();
    w.make_group(folder).unwrap();
    let a = w.create_in(db.me(), &[folder, db.home()]).unwrap();
    let b = w.create(db.me()).unwrap();
    w.at(a, ak("/t/x")).set(&Value::Int(1)).unwrap();
    w.commit().unwrap();
    assert_eq!(db.groups_of(a).within.into_iter().collect::<BTreeSet<_>>(), BTreeSet::from([folder, db.home()]));
    assert!(db.groups_of(b).within.is_empty());
    db.write_with(|w| {
        w.place(b, folder)?;
        w.unplace(a, db.home())
    })
    .unwrap();
    assert_eq!(db.groups_of(a).within, vec![folder]);
    let sub = db
        .write_with(|w| {
            let s = w.create(db.me())?;
            w.make_group(s)?;
            w.add_subgroup(folder, s)?;
            w.place(b, s)?;
            Ok(s)
        })
        .unwrap();
    assert!(db.groups_of(b).within.contains(&sub));
    assert!(db.groups_of(b).within.contains(&folder));
    db.write_with(|w| w.delete(a)).unwrap();
    assert!(db.groups_of(a).within.is_empty());
    assert_eq!(db.get(a, ak("/t/x")).unwrap(), None);
    // deleted: not known, though its creation stays held; a later write recreates it
    assert!(!db.knows(a) && db.created(a).is_some());
    db.write_with(|w| w.at(a, ak("/t/x")).set(&Value::Int(2))).unwrap();
    assert!(db.knows(a));
    // an unknown group or owner
    let mut w = db.write();
    let stranger = db_other_thing();
    assert_eq!(w.create(stranger), Err(Error::UnknownThing { tid: stranger }));
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
    let t = w.create(a.me()).unwrap();
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
    w.create(a.me()).unwrap();
    assert!(matches!(w.commit(), Err(Error::Permission { .. })));
    // signals need write too
    let mut w = b.write();
    w.at(t, osis::Lifetimes::signal(ak("/t/sig"))).set(&Value::Int(1)).unwrap();
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
    let x = w.create(a.me()).unwrap();
    let y = w.create(x).unwrap();
    let z = w.create(y).unwrap();
    for (i, t) in [x, y, z].into_iter().enumerate() {
        w.at(t, ak("/t/x")).set(&Value::Int(i as i64)).unwrap();
    }
    w.commit().unwrap().unwrap();
    deliver(&a, &b);
    for (i, t) in [x, y, z].into_iter().enumerate() {
        assert_eq!(b.owner_of(t), Some([a.me(), x, y][i]));
        assert!(b.created(t).is_some());
        assert_eq!(b.get(t, ak("/t/x")).unwrap(), Some(Value::Int(i as i64)));
    }
    let before = b.engine(|e| e.commit_ids().len());
    let mut w = b.write();
    let p = w.create(x).unwrap();
    w.create(p).unwrap();
    assert!(matches!(w.commit(), Err(Error::Permission { .. })));
    let mut w = b.write();
    let p = w.create(b.me()).unwrap();
    let q = w.create(z).unwrap();
    w.create(p).unwrap();
    w.create(q).unwrap();
    assert!(matches!(w.commit(), Err(Error::Permission { .. })));
    assert_eq!(b.engine(|e| e.commit_ids().len()), before);
}

// notes/api.md Writes: membership-class and synthetic aspects are not written by ops.
// spec/permissions.md §1
// spec/permissions.md §1 (membership-class by admins): writer side
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
    let db = Osis::create(cfg(1, MemStore::new(), &c)).unwrap().0;
    let (k, r) = (ak("/t/msg"), ak("/t/keep"));
    let mut w = db.write();
    let t = w.create(db.me()).unwrap();
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
// spec/commits.md §1
#[test]
fn act_as_spec_commits_1() {
    let db = db(1);
    let mut w = db.write();
    let t = w.create(db.me()).unwrap();
    w.at(t, ak("/t/y")).set(&Value::Int(0)).unwrap();
    let c1 = w.commit().unwrap().unwrap();
    let mut w = db.write();
    w.act_as(db.node());
    w.at(t, ak("/t/x")).set(&Value::Int(1)).unwrap();
    let c2 = w.commit().unwrap().unwrap();
    let actor = |c: osis::CommitId| db.engine(|e| e.header(&c).unwrap().actor);
    assert_eq!((actor(c1.id.commit().unwrap()), actor(c2.id.commit().unwrap())), (db.me(), db.node()));
    // an empty write commits nothing
    assert_eq!(db.write().commit().unwrap(), None);
}

// spec/permissions.md §7, notes/api.md Tids and moves: a moved thing reads through its old
// tid; same_thing is the explicit identity check.
#[test]
fn move_and_same_thing_spec_permissions_7() {
    let db = db(1);
    let mut w = db.write();
    let t = w.create(db.me()).unwrap();
    let owner2 = w.create(db.me()).unwrap();
    w.at(t, ak("/t/x")).set(&Value::Int(1)).unwrap();
    w.commit().unwrap();
    let m = db.move_thing(t, owner2, &[db.home()]).unwrap();
    assert_ne!(m, t);
    assert!(db.same_thing(t, m));
    assert!(!db.same_thing(t, owner2));
    assert_eq!(db.get(m, ak("/t/x")).unwrap(), Some(Value::Int(1)));
    assert_eq!(db.get(t, ak("/t/x")).unwrap(), Some(Value::Int(1)));
    assert!(db.groups_of(m).within.contains(&db.home()));
}

// notes/api.md Sync configuration and status: without a runtime the surface works locally,
// the stored server list survives a reopen, and waiting for another node fails `Network`.
// spec: none (API surface, notes/api.md)
#[test]
fn local_sync_surface_spec_api_sync() {
    let c = clock();
    let store = MemStore::new();
    let db = Osis::create(cfg(1, store.clone(), &c)).unwrap().0;
    assert!(db.servers().unwrap().is_empty());
    let st = db.status().unwrap();
    assert_eq!(st.groups.get(&db.home()).map(|g| g.state), Some(osis::SyncState::NoServers));
    assert!("".parse::<osis::ServerAddr>().is_err());
    let a = osis::ServerAddr::new("quic://h:1", [7; 32]);
    assert_eq!(a.to_string().parse::<osis::ServerAddr>().unwrap(), a);
    db.add_server(&a).unwrap();
    assert!(matches!(common::block_on(db.wait_synced(osis::SyncScope::All, std::time::Duration::from_secs(1))), Err(Error::Network(_))));
    drop(db);
    let db = Osis::open(cfg(1, store, &c)).unwrap();
    assert_eq!(db.servers().unwrap(), vec![a]);
}

// spec/data-model.md §9: `/created` is typed by its exclusivity rule (owner or key), not the
// missing-field rule, so a run-time core key (`Osis::key`, the CLI's) reads it.
#[test]
fn created_reads_through_run_time_key_spec_data_model_9() {
    let db = Osis::create(osis::Config::memory()).unwrap().0;
    let mut w = db.write();
    let t = w.create(db.me()).unwrap();
    w.commit().unwrap();
    let v = db.get(t, db.key("/created").unwrap()).unwrap().unwrap();
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
    let k = ak("/t/blob");
    let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let mut w = db.write();
    let t = w.create(db.me()).unwrap();
    w.at(t, k.clone()).set_stream(&data[..]).unwrap();
    w.commit().unwrap();
    assert_eq!(db.get(t, k.clone()), Err(Error::TooLarge { limit: 64 * 1024 }));
    assert_eq!(db.at(t, k.clone()).len().unwrap(), Some(300_000));
    let mut st = db.at(t, k.clone()).stream().unwrap().unwrap();
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
    let small = ak("/t/small");
    db.write_with(|w| w.at(t, small.clone()).set(&s("hello"))).unwrap();
    assert_eq!(db.at(t, small.clone()).len().unwrap(), Some(5));
    assert_eq!(db.at(t, ak("/t/none")).len().unwrap(), None);
    db.write_with(|w| w.at(t, ak("/t/n")).set(&Value::Int(1))).unwrap();
    assert!(matches!(db.at(t, ak("/t/n")).len(), Err(Error::Invalid(_))));
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
    });
    let mut w = db.write();
    let g = w.create(db.me()).unwrap();
    w.make_group(g).unwrap();
    // durable things: an ephemeral placement is no `NotSynced` matter (nothing leaves the
    // device anyway); placing a durable thing persists the group
    let home_item = w.create_durable(db.me()).unwrap();
    w.place(home_item, db.home()).unwrap();
    let lost = w.create_durable(db.me()).unwrap();
    w.place(lost, g).unwrap();
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
    let t = db.write_with(|w| {
        let t = w.create_in(db.me(), &[db.home()])?;
        w.at(t, ak("/t/x")).set(&Value::Int(1))?;
        w.at(t, ak("/t/y")).set(&Value::Int(2))?;
        Ok(t)
    }).unwrap();
    assert!(db.knows(t));
    let (tx, rx) = std::sync::mpsc::channel();
    let _sub = db.watch_thing(t, move |db, c| {
        let _ = tx.send((c.ak, c.value, db.knows(c.tid)));
    });
    db.settle();
    let initial: Vec<_> = rx.try_iter().collect();
    assert!(initial.iter().all(|(_, _, known)| *known), "{initial:?}");
    db.write_with(|w| w.delete(t)).unwrap();
    db.settle();
    let got: Vec<_> = rx.try_iter().collect();
    assert!(got.iter().any(|(ak, v, known)| ak.as_str() == "/t/x" && *v == Ok(None) && !known), "{got:?}");
    assert!(!db.knows(t) && db.created(t).is_some());
    assert!(!db.groups_of(db.home()).item_of.contains(&t) && !db.get(db.home(), core::GROUP).unwrap().unwrap().items.contains(&t));
    // an unknown tid: not known, no creation
    let other = db_other_thing();
    assert!(!db.knows(other) && db.created(other).is_none());
}

// notes/api.md Reads (groups_of), Writes (delete), spec/data-model.md §8: `groups_of` reports the
// groups listing a thing as an item and as a subgroup, and the transitive `/groups`; deleting a
// group removes its placements and the subgroup edges pointing at it.
#[test]
fn groups_of_relations_spec_data_model_8() {
    let db = db(1);
    let home = db.home();
    let (g1, g2, tag, x) = db.write_with(|w| {
        let group = |w: &mut osis::Write<'_>| -> osis::Result<osis::Tid> {
            let g = w.create_in(db.me(), &[home])?;
            w.make_group(g)?;
            w.add_subgroup(home, g)?;
            Ok(g)
        };
        let g1 = group(w)?;
        let g2 = group(w)?;
        let tag = w.create(db.me())?;
        w.make_group(tag)?;
        w.place(tag, g1)?;
        w.add_subgroup(g1, tag)?;
        w.add_subgroup(g2, tag)?;
        let x = w.create_durable(db.me())?;
        w.place(x, tag)?;
        Ok((g1, g2, tag, x))
    }).unwrap();
    let gs = db.groups_of(tag);
    assert_eq!(gs.item_of, vec![g1]);
    assert_eq!(gs.subgroup_of.iter().copied().collect::<BTreeSet<_>>(), BTreeSet::from([g1, g2]));
    assert_eq!(gs.within.iter().copied().collect::<BTreeSet<_>>(), BTreeSet::from([g1, home]), "an item's groups and those above them; not g2, which it is only a subgroup of");
    let gx = db.groups_of(x);
    assert_eq!(gx.item_of, vec![tag]);
    assert!(gx.subgroup_of.is_empty());
    assert_eq!(gx.within.iter().copied().collect::<BTreeSet<_>>(), BTreeSet::from([tag, g1, g2, home]));
    db.write_with(|w| w.delete(tag)).unwrap();
    assert_eq!(db.groups_of(tag), osis::GroupsOf::default());
    for g in [g1, g2] {
        let d = db.get(g, core::GROUP).unwrap().unwrap();
        assert!(!d.items.contains(&tag) && !d.subgroups.contains(&tag), "{g}: {d:?}");
    }
    assert!(!db.knows(tag));
    assert_eq!(db.groups_of(x).within, Vec::<osis::Tid>::new(), "its tag's /group went with it");
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
    let home = db.home();
    let g = db.write_with(|w| {
        let g = w.create_in(db.me(), &[home])?;
        w.make_group(g)?;
        Ok(g)
    }).unwrap();
    let mut w = db.write();
    let x = w.create_durable(db.me()).unwrap();
    w.place(x, g).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(m)) if m.contains("add_subgroup")));
    assert!(!db.knows(x) && db.created(x).is_none(), "nothing applied");
    // an ephemeral thing stays on this device anyway
    let e = db.write_with(|w| w.create_in(db.me(), &[g])).unwrap();
    assert!(db.groups_of(e).item_of.contains(&g));
    // ... until a durable write persists it with that placement: the same check
    let r = db.write_with(|w| w.at(e, ak("/t/x")).set(&Value::Int(1)));
    assert!(matches!(&r, Err(Error::Invalid(m)) if m.contains("add_subgroup")), "{r:?}");
    assert_eq!(db.created(e).unwrap().commit, None, "still ephemeral");
    // a group with no synced group at all: device-local, allowed (a `NotSynced` diagnostic)
    let local = db.write_with(|w| {
        let l = w.create_durable(db.me())?;
        w.make_group(l)?;
        let y = w.create_durable(db.me())?;
        w.place(y, l)?;
        Ok(l)
    }).unwrap();
    assert!(db.knows(local));
    // the fix: the group as a subgroup too, in the same batch
    let x = db.write_with(|w| {
        let x = w.create_durable(db.me())?;
        w.place(x, g)?;
        w.add_subgroup(home, g)?;
        Ok(x)
    }).unwrap();
    assert!(db.groups_of(x).within.contains(&home));
}

// notes/api.md Handle (close): close() from a callback fails at once (it would wait on the
// dispatcher that runs it); from the app it returns once the database is closed.
// spec: none (API surface, notes/api.md)
#[test]
fn close_spec_api_handle() {
    let db = db(1);
    let (tx, rx) = std::sync::mpsc::channel();
    let k = ak("/t/x");
    let mut w = db.write();
    let t = w.create(db.me()).unwrap();
    w.commit().unwrap();
    let sub = db.at(t, k).on_change(move |db, _| {
        let _ = tx.send(db.clone().close());
    }).unwrap();
    assert!(matches!(recv(&rx), Err(Error::Invalid(_))));
    drop(sub);
    let weak = db.downgrade();
    db.close().unwrap();
    assert!(weak.upgrade().is_none(), "closed when close() returns");
}

/// Writes a value nested past the depth limit, a string of `string` bytes and a map of `map`
/// entries; the database errs or accepts, never panics, and keeps working.
fn values_past_limits(string: usize, map: i64) {
    let db = db(1);
    let mut w = db.write();
    let t = w.create(db.me()).unwrap();
    w.commit().unwrap();
    let mut deep = Value::Int(0);
    for _ in 0..600 {
        deep = Value::List(vec![deep]);
    }
    assert!(db.write_with(|w| w.at(t, ak("/t/deep")).set(&deep)).is_err(), "nesting past the depth limit accepted");
    let huge = Value::Str("x".repeat(string));
    db.write_with(|w| w.at(t, ak("/t/huge")).set(&huge)).unwrap();
    assert_eq!(db.get(t, ak("/t/huge")).unwrap(), Some(huge));
    let big: BTreeMap<Value, Value> = (0..map).map(|i| (Value::Int(i), Value::Int(i))).collect();
    let _ = db.write_with(|w| w.at(t, ak("/t/map")).set(&Value::Map(big)));
    // still working
    db.write_with(|w| w.at(t, ak("/t/x")).set(&Value::Int(1))).unwrap();
    assert_eq!(db.get(t, ak("/t/x")).unwrap(), Some(Value::Int(1)));
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

// notes/api.md Writes (`place_expiring`, `expires`, `write_with`), spec/commits.md §6: a thing
// created with an expiring placement leaves its group at T by itself, its expiring value goes
// too; `expires(None)` is no expiry; a zero expiry is invalid; `write_with` returns the
// closure's value.
#[test]
fn expiring_placement_api_writes() {
    let c = clock();
    let db = Osis::create(cfg(1, MemStore::new(), &c)).unwrap().0;
    let (x, d) = (ak("/t/x"), Some(std::time::Duration::from_secs(60)));
    let gone = db
        .write_with(|w| {
            let t = w.create_expiring_in(db.me(), db.home(), d)?;
            w.at(t, x.clone()).expires(d).set(&s("bye"))?;
            Ok(t)
        })
        .unwrap();
    let kept = db
        .write_with(|w| {
            let t = w.create_expiring_in(db.me(), db.home(), None)?;
            w.at(t, x.clone()).expires(None).set(&s("stays"))?;
            Ok(t)
        })
        .unwrap();
    let items = |db: &Osis| db.get(db.home(), core::GROUP).unwrap().unwrap().items;
    assert!(items(&db).contains(&gone) && items(&db).contains(&kept));
    c.advance(61_000);
    db.engine(|e| e.tick()).unwrap();
    assert!(!items(&db).contains(&gone), "the placement expired");
    assert!(items(&db).contains(&kept));
    assert_eq!(db.get(gone, x.clone()).unwrap(), None);
    assert_eq!(db.get(kept, x.clone()).unwrap(), Some(s("stays")));
    let mut w = db.write();
    assert!(matches!(w.create_expiring_in(db.me(), db.home(), Some(std::time::Duration::ZERO)), Err(Error::Invalid(_))));
    assert!(matches!(w.at(kept, x).expires(Some(std::time::Duration::ZERO)).set(&s("now")), Err(Error::Invalid(_))));
    // one batch cannot mix expiries on one group's `/group` (expiry is per aspect write)
    drop(w);
    let mut w = db.write();
    let g = w.create(db.me()).unwrap();
    w.make_group(g).unwrap();
    assert!(matches!(w.create_expiring_in(db.me(), g, d), Err(Error::Invalid(_))), "the group's definition would expire");
    drop(w);
    let mut w = db.write();
    w.create_expiring_in(db.me(), db.home(), d).unwrap();
    w.create_expiring_in(db.me(), db.home(), d).unwrap();
    assert!(matches!(w.create_expiring_in(db.me(), db.home(), Some(std::time::Duration::from_secs(5))), Err(Error::Invalid(_))));
    assert!(matches!(w.create_in(db.me(), &[db.home()]), Err(Error::Invalid(_))));
    drop(w);
    // the `/group` field constants are the ones `place` writes
    assert_eq!(db.at(db.home(), core::GROUP).path(p![core::group::ITEMS]).get::<BTreeSet<osis::Tid>>().unwrap(), Some(items(&db)));
}

// spec/commits.md §2 (`/created`); notes/api.md Reads (`owner_of`, `created`, `now`): the owner fixed at creation, the creating
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
    assert_eq!(db.owner_of(t), Some(db.me()));
    let ci = db.created(t).unwrap();
    assert_eq!((ci.commit, ci.ts, ci.node, ci.actor, ci.received), (done.id.commit(), done.ts, db.node(), db.me(), osis::WallMs(T0 + 5)));
    assert_eq!(ci.shown(), osis::WallMs(T0 + 5));
    c.advance(5);
    db.write_with(|w| w.at(t, ak("/t/x")).set(&s("later"))).unwrap();
    assert_eq!(db.created(t).unwrap(), ci, "the creation, not the newest commit");
    let other = common::db(2);
    assert_eq!(db.owner_of(other.me()), None);
    assert_eq!(db.created(other.me()), None);
}

// notes/api.md Reads (`changed`): a thing's last content change, shown at `min(ts, received)`:
// the creation until content changes; placement is no change of the item nor of the group's
// content; a device whose clock runs ahead dates its change at its receipt here, and the
// latest shown change wins over one with a higher `ts`; a delete is a change; an ephemeral
// thing reports its creation.
#[test]
fn changed_content_only_api_reads() {
    let (ca, cb) = (clock(), clock());
    let a = Osis::create(cfg(1, MemStore::new(), &ca)).unwrap().0;
    let j = Osis::pair(cfg(2, MemStore::new(), &cb), &a.pair_offer().unwrap()).unwrap();
    let (_, reply) = a.pair_accept(j.request()).unwrap();
    let b = j.finish(&reply).unwrap();
    let t = a
        .write_with(|w| {
            let t = w.create_durable(a.me())?;
            w.place(t, a.home())?;
            Ok(t)
        })
        .unwrap();
    assert_eq!(a.changed(t), a.created(t));
    ca.advance(10);
    a.write_with(|w| w.at(t, ak("/t/x")).set(&s("1"))).unwrap();
    let ch = a.changed(t).unwrap();
    assert_eq!((ch.commit, ch.shown()), (Some(newest(&a, t)), osis::WallMs(T0 + 10)));
    assert_ne!(a.created(t), Some(ch));
    // placement: neither the item's nor the group's content
    let home = a.changed(a.home());
    ca.advance(10);
    let g = a.write_with(|w| w.create_durable(a.me())).unwrap();
    a.write_with(|w| {
        w.place(t, g)?;
        w.unplace(t, a.home())
    })
    .unwrap();
    assert_eq!((a.changed(t), a.changed(a.home())), (Some(ch), home));
    // b's clock runs 30 min ahead (within MAX_DRIFT): its change shows at its receipt here
    deliver(&a, &b);
    cb.advance(30 * 60_000);
    b.write_with(|w| w.at(t, ak("/t/x")).set(&s("2"))).unwrap();
    deliver(&b, &a);
    let ch = a.changed(t).unwrap();
    assert_eq!((ch.node, ch.ts.wall_ms(), ch.shown()), (b.node(), osis::WallMs(T0 + 30 * 60_000), osis::WallMs(T0 + 20)));
    // a's next change: its ts follows b's (the clock rule), shown latest at its receipt
    ca.advance(10);
    a.write_with(|w| w.at(t, ak("/t/y")).set(&s("3"))).unwrap();
    let ch = a.changed(t).unwrap();
    assert_eq!((ch.node, ch.shown()), (a.node(), osis::WallMs(T0 + 30)));
    ca.advance(10);
    a.write_with(|w| w.delete(t)).unwrap();
    assert!(!a.knows(t));
    assert_eq!(a.changed(t).unwrap().shown(), osis::WallMs(T0 + 40), "a delete is a change");
    let mut w = a.write();
    let e = w.create(a.me()).unwrap();
    w.at(e, osis::Lifetimes::ephemeral(ak("/t/x"))).set(&s("draft")).unwrap();
    w.commit().unwrap();
    assert!(a.created(e).unwrap().commit.is_none());
    assert_eq!(a.changed(e), a.created(e));
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
    let r = ak("/t/reactions");
    let t = a.write_with(|w| w.create_durable(a.me())).unwrap();
    deliver(&a, &b);
    a.write_with(|w| w.at(t, r.clone()).path(p!["m1"]).add(&s("x"))).unwrap();
    b.write_with(|w| w.at(t, r.clone()).path(p!["m1"]).add(&s("y"))).unwrap();
    deliver(&a, &b);
    deliver(&b, &a);
    let want = Value::Map(BTreeMap::from([(s("m1"), Value::Set(BTreeSet::from([s("x"), s("y")])))]));
    assert_eq!(a.get(t, r.clone()).unwrap(), Some(want.clone()));
    assert_eq!(b.get(t, r).unwrap(), Some(want));
}

// spec/commits.md §2 (`/created` is carried by the first commit and by covering snapshots),
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
    let t = w.create(a.me()).unwrap();
    w.at(t, ak("/t/x")).set(&s("v")).unwrap();
    let done = w.commit().unwrap().unwrap();
    c.advance(60_000);
    let snap = a.engine(|e| e.snapshot(&t, &ak("/t/x"))).unwrap().unwrap();
    assert_eq!(a.created(t).unwrap().commit, Some(done.id.commit().unwrap()));
    let pks = a.engine(|e| e.commit_ids().iter().filter(|id| **id != done.id.commit().unwrap()).filter_map(|id| e.package(id).unwrap()).collect::<Vec<_>>());
    for pk in pks {
        b.engine(|e| e.ingest(&pk.bytes, pk.blobs.clone()).unwrap());
    }
    assert!(b.engine(|e| e.header(&done.id.commit().unwrap())).is_none());
    let _ = snap;
    assert_eq!(b.created(t), None);
}
