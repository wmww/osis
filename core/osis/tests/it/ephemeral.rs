//! Local drafts and aspects (notes/ephemeral.md, step 1): in memory, no commit, no
//! store write; persistence at the first durable write with the record chain; restart forgets;
//! rights through the nearest durable first admin; expiry in memory; signal aspects.

use osis::internals::Exact as _;
use osis::internals::CommitRaw as _;
use crate::common::watched;
use crate::common::TestWrites as _;
use osis::internals::Internals as _;
use crate::common::*;
use crate::common::CreateIn;
use osis_sim::world::World;
use osis::{Error, MemStore, Osis, Role, Origin, Store, Value};
use std::sync::mpsc::channel;
use std::time::Duration;

const SCHEMA: &str = "version 1;\n\
type win = struct { 0 title: string, 1 notes: list<string> };\n\
aspect win:state.0~: win;\n\
aspect win:typing.0~: bool [expires: 5s];\n\
aspect win:cursor.0~: map<tid, int> [expires: 30s];\n\
aspect win:ring.0*: string;\n\
aspect win:saved.0: string;\n";

fn setup(seed: u64) -> (Osis, std::sync::Arc<osis::internals::ManualClock>) {
    let c = clock();
    let db = osis::internals::create(cfg(seed, MemStore::new(), &c)).unwrap();
    db.register_schema("win.osis", SCHEMA).unwrap();
    (db, c)
}

/// The held commits: a commit that fails leaves none (its transaction rolls back; the engine
/// generation moves with the rollback, so it is no mark).
fn durable_marks(db: &Osis) -> usize {
    db.engine(|e| e.commit_ids().len())
}

fn field(id: u64) -> osis::Path {
    osis::Path(vec![osis::Step::Field(id)])
}

fn s(x: &str) -> Value {
    Value::Str(x.into())
}

// notes/ephemeral.md Model, Local engine: a draft and its ephemeral aspects (typed,
// with path ops) are written, read and watched with no commit and no store write; an
// ephemeral aspect of a durable thing likewise. spec/data-model.md §1, §2
#[test]
fn write_and_watch_without_commit_spec_data_model_2() {
    let (db, _c) = setup(1);
    let state = db.aspect_key("win:state.0~").unwrap();
    let before = durable_marks(&db);
    let mut w = db.write();
    let win = w.create().unwrap();
    w.at(win, state.clone()).set(&Value::Map([(Value::Int(0), s("draft")), (Value::Int(1), Value::List(vec![s("a")]))].into())).unwrap();
    let done = w.commit().unwrap().unwrap();
    assert!(done.id.commit().is_none());
    assert_eq!(durable_marks(&db), before, "no commit, no store write");
    assert!(db.has_content(win).unwrap());
    assert_eq!(db.owner_of(win).unwrap(), Some(db.me()));
    let c = db.created(win).unwrap().unwrap();
    assert_eq!((c.id, c.ts(), c.node, c.actor), (None, done.ts(), db.node(), db.me()));
    assert_eq!(db.role_on(win).unwrap(), Some(Role::Admin));
    assert_eq!(db.at(win, state.clone()).path(field(0)).get::<String>().unwrap().as_deref(), Some("draft"));
    let (tx, rx) = channel();
    let _sub = db.at(win, state.clone()).on_change(move |_, c| tx.send(c).unwrap()).unwrap();
    assert_eq!(recv(&rx).origin, Origin::Initial);
    let watch = watched(&db, win, state.clone()).unwrap();
    // a path op on the list inside the value
    let mut w = db.write();
    w.at(win, state.clone()).path(field(1)).splice(1..1, &[s("b")]).unwrap();
    let done = w.commit().unwrap().unwrap();
    let ch = recv(&rx);
    match ch.origin {
        Origin::Local(i) => assert_eq!((i.id, i.ts(), i.node), (done.id, done.ts(), db.node())),
        other => panic!("{other:?}"),
    }
    assert_eq!(db.at(win, state.clone()).path(field(1)).get::<Vec<String>>().unwrap(), Some(vec!["a".to_string(), "b".to_string()]));
    assert!(watch.changed_timeout(Duration::from_secs(20)));
    assert!(watch.current().unwrap().is_some());
    assert_eq!(db.aspects(win).unwrap(), vec![osis::Ak::new("win:state.0~").unwrap()]);
    // an ephemeral aspect of a durable thing
    let cur = ak("app:selection.0~");
    db.commit_set(db.me(), osis::DynamicAspectKey::untyped(cur.clone()), &Value::Int(7)).unwrap();
    assert_eq!(db.at(db.me(), osis::DynamicAspectKey::untyped(cur)).get().unwrap(), Some(Value::Int(7)));
    assert_eq!(durable_marks(&db), before);
    assert!(db.aspects(db.me()).unwrap().contains(&ak("app:selection.0~")));
}

// notes/ephemeral.md Persistence: the first durable write on a draft persists it
// and its ephemeral record chain in one commit, keeping the tids; its ephemeral aspects stay
// ephemeral. spec/data-model.md §1, spec/commits.md §2
#[test]
fn first_durable_write_persists_chain_spec_commits_2() {
    let (db, _c) = setup(2);
    let state = db.aspect_key("win:state.0~").unwrap();
    let saved = db.aspect_key("win:saved.0").unwrap();
    let (top, mid, leaf) = db
        .commit_with(|w| {
            let top = w.create()?;
            let mid = w.create_owned_by(top)?;
            let leaf = w.create_owned_by(mid)?;
            w.at(leaf, osis::DynamicAspectKey::untyped(ak("app:draft.0~"))).set(&s("hello"))?;
            Ok((top, mid, leaf))
        })
        .unwrap();
    let mut w = db.write();
    let other = w.create().unwrap();
    w.commit().unwrap();
    let before = db.engine(|e| e.commit_ids().len());
    let mut w = db.write();
    w.at(leaf, saved.clone()).set(&s("hello")).unwrap();
    w.commit().unwrap();
    let mut w = db.write();
    w.at(leaf, state.clone()).set(&Value::Map([(Value::Int(0), s("t")), (Value::Int(1), Value::List(vec![]))].into())).unwrap();
    w.commit().unwrap();
    assert_eq!(db.engine(|e| e.commit_ids().len()), before + 1, "one commit");
    let c = db.created(leaf).unwrap().unwrap().id.expect("durable now");
    assert_eq!(db.created(mid).unwrap().unwrap().id, Some(c));
    assert_eq!(db.created(top).unwrap().unwrap().id, Some(c));
    assert_eq!(db.created(other).unwrap().unwrap().id, None, "untouched things stay ephemeral");
    let h = db.engine(|e| e.header(&c.commit().unwrap())).unwrap();
    let created: Vec<osis::Tid> = h.aspects.iter().filter(|a| a.ak.as_str() == "created.0").map(|a| a.tid).collect();
    assert_eq!(created.len(), 3);
    assert!([top, mid, leaf].iter().all(|t| created.contains(t)));
    assert!(h.aspects.iter().all(|a| a.ak.as_str() != "win:state.0~" && a.ak.as_str() != "app:draft.0~"), "ephemeral aspects stay out of the commit");
    assert_eq!(db.at(leaf, saved).get().unwrap(), Some(s("hello")));
    assert_eq!(db.at(leaf, osis::DynamicAspectKey::untyped(ak("app:draft.0~"))).get().unwrap(), Some(s("hello")));
    assert!(db.at(leaf, state).get().unwrap().is_some());
    // placing a draft keeps it ephemeral (notes/ephemeral.md (`ephemeral_group.0~`))
    let mut w = db.write();
    w.group(db.me()).add(osis::Member::Item(other)).unwrap();
    w.commit().unwrap();
    assert_eq!(db.created(other).unwrap().unwrap().id, None);
    assert!(db.groups_of(other).unwrap().within.contains(&db.me()));
}

// notes/ephemeral.md Local engine (Restart): on a `Dir` store, reopening forgets every
// draft and ephemeral aspect; durable data is intact. spec/requirements.md (data
// model: ephemeral state in memory)
// spec/data-model.md §1
#[test]
fn restart_forgets_ephemeral_spec_requirements_ephemeral() {
    let dir = std::env::temp_dir().join(format!("osis-eph-{}-{:?}", std::process::id(), std::thread::current().id()).replace(['(', ')'], ""));
    let _ = std::fs::remove_dir_all(&dir);
    let c = clock();
    let at = |seed: u64| {
        let mut x = osis::internals::Opening::at(Store::Dir(dir.clone()));
        x.app.internals.seed = Some(seed);
        x.app.internals.clock = Some(c.clone());
        x
    };
    let db = osis::internals::create(at(1)).unwrap();
    let draft = ak("app:draft.0~");
    let (d, e) = db
        .commit_with(|w| {
            let d = w.create()?;
            w.at(d, osis::DynamicAspectKey::untyped(ak("app:kept.0"))).set(&Value::Int(1))?;
            let e = w.create()?;
            Ok((d, e))
        })
        .unwrap();
    db.commit_with(|w| {
        w.at(d, osis::DynamicAspectKey::untyped(draft.clone())).set(&Value::Int(2))?;
        w.at(e, osis::DynamicAspectKey::untyped(draft.clone())).set(&Value::Int(3))
    })
    .unwrap();
    assert_eq!(db.at(e, osis::DynamicAspectKey::untyped(draft.clone())).get().unwrap(), Some(Value::Int(3)));
    assert_eq!(db.close().unwrap(), osis::Close::Closed);
    let db = osis::internals::open(at(2)).unwrap();
    assert!(!db.has_content(e).unwrap());
    assert_eq!(db.at(e, osis::DynamicAspectKey::untyped(draft.clone())).get().unwrap(), None);
    assert_eq!(db.at(d, osis::DynamicAspectKey::untyped(ak("app:kept.0"))).get().unwrap(), Some(Value::Int(1)));
    assert_eq!(db.at(d, osis::DynamicAspectKey::untyped(draft)).get().unwrap(), None);
    assert_eq!(db.close().unwrap(), osis::Close::Closed);
    let _ = std::fs::remove_dir_all(&dir);
}

// notes/ephemeral.md Rights: a draft's role is the role on a new thing under the
// nearest durable thing of its chain; a node with no write there can neither create one nor
// write ephemeral data on another's thing. spec/permissions.md §1
#[test]
fn rights_through_nearest_durable_first_admin_spec_permissions_1() {
    let (a, _c) = setup(3);
    let (b, _c2) = setup(4);
    let mut w = a.write();
    let t = w.create().unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(ak("app:kept.0"))).set(&Value::Int(1)).unwrap();
    w.commit().unwrap();
    deliver(&a, &b);
    assert_eq!(b.role_on(t).unwrap(), None);
    let before = durable_marks(&b);
    // a draft under another actor's thing
    let mut w = b.write();
    w.create_owned_by(t).unwrap();
    assert!(matches!(w.commit(), Err(Error::Permission { .. })));
    // ephemeral data on another actor's durable thing
    let mut w = b.write();
    w.at(t, osis::DynamicAspectKey::untyped(ak("app:cursor.0~"))).set(&Value::Int(1)).unwrap();
    assert_eq!(w.commit(), Err(Error::Permission { tid: t, needs: Role::Write }));
    assert_eq!(b.at(t, osis::DynamicAspectKey::untyped(ak("app:cursor.0~"))).get().unwrap(), None);
    assert_eq!(durable_marks(&b), before);
    // a's own ephemeral chain under t: admin through t
    let (x, y) = a
        .commit_with(|w| {
            let x = w.create_owned_by(t)?;
            let y = w.create_owned_by(x)?;
            Ok((x, y))
        })
        .unwrap();
    assert_eq!(a.role_on(y).unwrap(), a.role_on(t).unwrap());
    assert_eq!(a.role_on(x).unwrap(), Some(Role::Admin));
    assert!(!b.has_content(y).unwrap());
}

// notes/ephemeral.md Expiry: an expiring ephemeral write (explicit, or the key's default) goes
// at T in memory, without a commit; watches see `Derived(Expiry)`. spec/crdt.md §4.7
#[test]
fn ephemeral_expiry_spec_crdt_4_7() {
    let (db, c) = setup(5);
    let typing = db.aspect_key("win:typing.0~").unwrap();
    let note = ak("app:note.0~");
    let mut w = db.write();
    let t = w.create().unwrap();
    w.at(t, typing.clone()).set(&Value::Bool(true)).unwrap();
    w.commit().unwrap();
    let mut w = db.write();
    w.expires(osis::Expiry::In(Duration::from_secs(60)));
    w.at(t, osis::DynamicAspectKey::untyped(note.clone())).set(&s("bye")).unwrap();
    w.commit().unwrap();
    let before = durable_marks(&db);
    let (tx, rx) = channel();
    let _sub = db.at(t, typing.clone()).on_change(move |_, c| tx.send(c).unwrap()).unwrap();
    recv(&rx);
    assert_eq!(db.engine(|e| e.next_timer().unwrap()), Some(T0 + 5_000));
    c.advance(4_000);
    db.engine(|e| e.tick().unwrap());
    assert_eq!(db.at(t, typing.clone()).get().unwrap(), Some(Value::Bool(true)));
    c.advance(2_000);
    db.engine(|e| e.tick().unwrap());
    let ch = recv(&rx);
    assert_eq!((ch.origin, ch.value), (Origin::Derived(osis::DerivedFrom::Expired), Ok(None)));
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(note.clone())).get().unwrap(), Some(s("bye")));
    // a later write of the same aspect is not touched by the old class
    let mut w = db.write();
    w.expires(osis::Expiry::In(Duration::from_secs(30)));
    w.at(t, typing.clone()).set(&Value::Bool(true)).unwrap();
    w.commit().unwrap();
    assert_eq!(db.at(t, typing).get().unwrap(), Some(Value::Bool(true)));
    c.advance(60_000);
    db.engine(|e| e.tick().unwrap());
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(note)).get().unwrap(), None);
    assert_eq!(durable_marks(&db), before);
    let mut w = db.write();
    w.expires(osis::Expiry::In(Duration::ZERO));
    w.at(t, osis::DynamicAspectKey::untyped(ak("app:x.0~"))).set(&Value::Int(1)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(_))));
}

// notes/ephemeral.md Model (signal aspects): each set reaches every callback once, never in
// state (reads and watches stay absent); any other op is Invalid. spec/data-model.md §2
#[test]
fn signal_aspects_fire_once_never_in_state_spec_data_model_2() {
    let (db, _c) = setup(6);
    let ring = db.aspect_key("win:ring.0*").unwrap();
    let mut w = db.write();
    let t = w.create().unwrap();
    w.commit().unwrap();
    let (tx, rx) = channel();
    let _sub = db.at(t, ring.clone()).on_change(move |_, c| tx.send(c).unwrap()).unwrap();
    assert_eq!(recv(&rx).value, Ok(None));
    let (ttx, trx) = channel();
    let _th = db.on_thing_change(t, move |_, c| ttx.send(c).unwrap()).unwrap();
    let before = durable_marks(&db);
    for _ in 0..2 {
        db.commit_set(t, ring.clone(), &s("ding")).unwrap();
    }
    for _ in 0..2 {
        let c = recv(&rx);
        assert_eq!(c.value, Ok(Some(s("ding"))));
        assert!(matches!(c.origin, Origin::Local(_)));
        assert_eq!(recv(&trx).value, Ok(Some(s("ding"))));
    }
    db.settle();
    assert!(rx.try_recv().is_err(), "once each");
    assert_eq!(db.at(t, ring.clone()).get().unwrap(), None, "a signal holds nothing");
    assert!(db.aspects(t).unwrap().is_empty());
    assert_eq!(durable_marks(&db), before);
    let mut w = db.write();
    w.at(t, ring.clone()).remove().unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(_))));
    let mut w = db.write();
    w.at(t, osis::DynamicAspectKey::untyped(ak("app:sig.0*"))).path(osis::p!["k"]).set(&Value::Int(1)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(_))));
}

// spec/commits.md §2, notes/api.md Writes: a commit is durable or ephemeral. A write asking for both
// is refused, naming both, before anything applies, whatever else is wrong with it; so are signals
// beside either, and ephemeral writes of two expiries. Written apart each is one commit of its own.
#[test]
fn durable_beside_ephemeral_refused_spec_commits_2() {
    let (a, _c) = setup(7);
    let (b, _c2) = setup(8);
    let mut w = a.write();
    let t = w.create().unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(ak("app:kept.0"))).set(&Value::Int(1)).unwrap();
    w.commit().unwrap();
    deliver(&a, &b);
    let draft = ak("app:draft.0~");
    let kept = ak("app:kept.0");
    let mut w = b.write();
    let e = w.create().unwrap();
    w.at(b.me(), osis::DynamicAspectKey::untyped(draft.clone())).set(&Value::Int(1)).unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(kept.clone())).set(&Value::Int(2)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(m)) if m.contains("app:draft.0~") && m.contains("app:kept.0")));
    assert!(!b.has_content(e).unwrap());
    assert_eq!(b.at(b.me(), osis::DynamicAspectKey::untyped(draft.clone())).get().unwrap(), None);
    // an ephemeral op takes no retention
    let before = durable_marks(&b);
    let mut w = b.write();
    w.at(b.me(), osis::DynamicAspectKey::untyped(draft.clone())).retention(osis::Retention::default()).set(&Value::Int(1)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(_))));
    assert_eq!(durable_marks(&b), before);
    // a draft's membership in a durable group is ephemeral: not beside a durable write
    let group = b.commit_with(|w| {
        let g = w.create()?;
        w.at(g, osis::DynamicAspectKey::untyped(kept.clone())).set(&Value::Int(1))?;
        Ok(g)
    })
    .unwrap();
    let mut w = b.write();
    let d = w.create().unwrap();
    w.group(group).add(osis::Member::Item(d)).unwrap();
    w.at(b.me(), osis::DynamicAspectKey::untyped(kept.clone())).set(&Value::Int(3)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(m)) if m.contains("the members of") && m.contains("app:kept.0")));
    // nor a signal beside an ephemeral write
    let mut w = b.write();
    w.at(b.me(), osis::DynamicAspectKey::untyped(ak("app:ring.0*"))).set(&Value::Int(1)).unwrap();
    w.at(b.me(), osis::DynamicAspectKey::untyped(draft.clone())).set(&Value::Int(1)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(m)) if m.contains("signal")));
    // nor ephemeral writes of two expiries
    b.register_schema("cursor.osis", "version 1;\naspect app:cursor.0~: int [expires: 30s];").unwrap();
    let mut w = b.write();
    w.at(b.me(), b.aspect_key("app:cursor.0~").unwrap()).set(&Value::Int(1)).unwrap();
    w.at(b.me(), osis::DynamicAspectKey::untyped(draft.clone())).set(&Value::Int(1)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(m)) if m.contains("one expiry")));
    assert_eq!(durable_marks(&b), before + 1, "only the group's commit applied");
    // a delete is no way past it: what it ends follows the durable commit, what is asked beside it
    // does not, a durable thing's delete with an ephemeral write elsewhere or a signal on it
    let gone = b.commit_with(|w| {
        let g = w.create()?;
        w.at(g, osis::DynamicAspectKey::untyped(kept.clone())).set(&Value::Int(1))?;
        Ok(g)
    })
    .unwrap();
    let marks = durable_marks(&b);
    let mut w = b.write();
    w.delete(gone).unwrap();
    w.at(b.me(), osis::DynamicAspectKey::untyped(draft.clone())).set(&Value::Int(1)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(m)) if m.contains("app:draft.0~") && m.contains("app:kept.0")));
    let mut w = b.write();
    w.delete(gone).unwrap();
    w.at(gone, osis::DynamicAspectKey::untyped(ak("app:ring.0*"))).set(&Value::Int(1)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(m)) if m.contains("app:ring.0*")));
    assert_eq!((durable_marks(&b), b.has_content(gone).unwrap()), (marks, true), "nothing applied");
    // apart: the durable one a commit, the ephemeral one with an id of its own, each what its watch names
    let (tx, rx) = channel();
    let _sub = b.at(b.me(), osis::DynamicAspectKey::untyped(draft.clone())).on_change(move |_, c| tx.send(c).unwrap()).unwrap();
    recv(&rx);
    let done = commit_with(&b, |w| w.at(b.me(), osis::DynamicAspectKey::untyped(kept.clone())).set(&Value::Int(3)));
    let c = done.id.commit().expect("a commit");
    assert_eq!(b.engine(|e| e.header(&c)).unwrap().ts, done.ts());
    let own = commit_with(&b, |w| w.at(b.me(), osis::DynamicAspectKey::untyped(draft.clone())).set(&Value::Int(4)));
    assert!(own.id.commit().is_none());
    assert_ne!(own.id, done.id);
    match recv(&rx).origin {
        Origin::Local(i) => assert_eq!((i.id, i.ts()), (own.id, own.ts())),
        other => panic!("{other:?}"),
    }
    // a draft with only an expiring ephemeral write is one commit: its record rides beside it
    let (draft_t, soon) = {
        let mut w = b.write();
        let x = w.create().unwrap();
        w.expires(osis::Expiry::In(Duration::from_secs(5)));
        w.at(x, osis::DynamicAspectKey::untyped(draft.clone())).set(&Value::Int(1)).unwrap();
        (x, w.commit().unwrap().unwrap())
    };
    assert!(soon.id.commit().is_none());
    assert_eq!(b.at(draft_t, osis::DynamicAspectKey::untyped(draft.clone())).get().unwrap(), Some(Value::Int(1)));
    // a draft with only an expiring durable write is refused: its record does not expire
    let mut w = b.write();
    let x = w.create().unwrap();
    w.expires(osis::Expiry::In(Duration::from_secs(5)));
    w.at(x, osis::DynamicAspectKey::untyped(kept.clone())).set(&Value::Int(1)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(m)) if m.contains("record")));
    assert!(!b.has_content(x).unwrap());
}

// notes/ephemeral.md Deletion: deleting a draft in no labeled closure frees it with
// the drafts it owns; the tids read unknown.
// spec/data-model.md §1
#[test]
fn delete_frees_drafts() {
    let (db, _c) = setup(9);
    let draft = ak("app:draft.0~");
    let (x, y) = db
        .commit_with(|w| {
            let x = w.create()?;
            let y = w.create_owned_by(x)?;
            w.at(x, osis::DynamicAspectKey::untyped(draft.clone())).set(&Value::Int(1))?;
            w.at(y, osis::DynamicAspectKey::untyped(draft.clone())).set(&Value::Int(2))?;
            w.group(db.me()).add(osis::Member::Item(y))?;
            Ok((x, y))
        })
        .unwrap();
    let (tx, rx) = channel();
    let _sub = db.at(x, osis::DynamicAspectKey::untyped(draft.clone())).on_change(move |_, c| tx.send(c).unwrap()).unwrap();
    recv(&rx);
    let mut w = db.write();
    w.delete(x).unwrap();
    w.commit().unwrap();
    assert_eq!(recv(&rx).value, Ok(None));
    assert!(!db.has_content(x).unwrap() && !db.has_content(y).unwrap());
    assert_eq!(db.at(y, osis::DynamicAspectKey::untyped(draft)).get().unwrap(), None);
    assert!(!group_of(&db, db.me()).items.contains(&y), "an owned thing's membership goes with it");
    let mut w = db.write();
    assert_eq!(w.create_owned_by(x), Err(Error::UnknownThing { tid: x }));
}

fn bench_n() -> i64 {
    std::env::var("OSIS_BENCH_N").ok().and_then(|v| v.parse().ok()).unwrap_or(100_000)
}

// notes/ephemeral.md Local engine (cost): `OSIS_BENCH_N` local ephemeral sets of one aspect,
// each its own commit, against `bench_btreemap_sets`; compare with tools/icount on a release
// build (notes/testing.md), subtracting a run with `OSIS_BENCH_N=0`. spec: none (cost)
#[test]
#[ignore = "bench: release, by hand"]
fn bench_ephemeral_sets() {
    let n = bench_n();
    let db = db(1);
    // `OSIS_BENCH_DURABLE=1`: the same through durable commits, for comparison
    let k = ak(if std::env::var_os("OSIS_BENCH_DURABLE").is_some() { "app:x.0" } else { "app:x.0~" });
    let mut w = db.write();
    let t = w.create_durable(db.me()).unwrap();
    w.commit().unwrap();
    for i in 0..n {
        db.commit_set(t, osis::DynamicAspectKey::untyped(k.clone()), &Value::Int(i)).unwrap();
    }
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(k)).get().unwrap(), (n > 0).then(|| Value::Int(n - 1)));
}

// The write path's commit cost (notes/client-port.md §1): `OSIS_BENCH_N` map puts into one
// durable aspect in one commit: recording, building the mutation, one commit. spec: none (cost)
#[test]
#[ignore = "bench: release, by hand"]
fn bench_commit_puts() {
    let n = bench_n();
    let db = db(1);
    let k = ak("app:m.0");
    let mut w = db.write();
    let t = w.create_durable(db.me()).unwrap();
    w.commit().unwrap();
    let mut w = db.write();
    let mut a = w.at(t, osis::DynamicAspectKey::untyped(k.clone()));
    for i in 0..n {
        a.path(osis::p!(Value::Int(i))).set(&Value::Int(i)).unwrap();
    }
    w.commit().unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(k)).path(osis::p!(Value::Int(0))).get::<Value>().unwrap().is_some(), n > 0);
}

// The baseline of `bench_ephemeral_sets`: the same sets into an in-memory map. spec: none (cost)
#[test]
#[ignore = "bench: release, by hand"]
fn bench_btreemap_sets() {
    let n = bench_n();
    let t = db(1).me();
    let mut m = std::collections::BTreeMap::new();
    for i in 0..n {
        m.insert((t, "app:x.0~".to_string()), Value::Int(i));
    }
    assert_eq!(std::hint::black_box(m).len(), usize::from(n > 0));
}



/// Alice's synced group `g` with Bob granted `role` on it, through one host.
/// `shared` with a second group of alice's, `bob` holding `role2` on it.
fn shared_two(role: Role, role2: Role) -> (World, Osis, Osis, osis::Tid, osis::Tid) {
    let (mut w, alice, bob, g) = shared(role);
    let card = bob.contact_card().unwrap();
    let b = w.until(alice.import_contact(&card), 1000, 10).unwrap();
    let mut wr = alice.write();
    let g2 = wr.create().unwrap();
    wr.group(alice.me()).add(osis::Member::Item(g2)).unwrap();
    wr.commit().unwrap();
    alice.sync(g2, &[]).unwrap();
    alice.grant(g2, b, role2, Default::default()).unwrap();
    w.run();
    (w, alice, bob, g, g2)
}

fn shared(role: Role) -> (World, Osis, Osis, osis::Tid) {
    let mut w = World::new();
    let host = w.add_host();
    let alice = w.account(1, &[host]);
    let bob = w.account(2, &[host]);
    w.run();
    let card = bob.contact_card().unwrap();
    w.run();
    let b = w.until(alice.import_contact(&card), 1000, 10).unwrap();
    let mut wr = alice.write();
    let g = wr.create().unwrap();
    wr.group(alice.me()).add(osis::Member::Item(g)).unwrap();
    wr.commit().unwrap();
    alice.sync(g, &[]).unwrap();
    alice.grant(g, b, role, Default::default()).unwrap();
    w.run();
    (w, alice, bob, g)
}

// notes/ephemeral.md Rights: readers cannot write ephemeral data (spec/requirements.md: readers
// only read): a reader of the nearest durable first admin can neither create a draft under
// it, write an ephemeral aspect on it nor fire a signal there; a writer can.
// spec/permissions.md §1
#[test]
fn reader_cannot_write_ephemeral_spec_permissions_1() {
    let (_w, _alice, bob, g) = shared(Role::Read);
    assert_eq!(bob.role_on(g).unwrap(), Some(Role::Read));
    let before = durable_marks(&bob);
    let mut w = bob.write();
    w.create_owned_by(g).unwrap();
    assert!(matches!(w.commit(), Err(Error::Permission { .. })), "a reader creates under g");
    let mut w = bob.write();
    w.at(g, osis::DynamicAspectKey::untyped(ak("app:cursor.0~"))).set(&Value::Int(1)).unwrap();
    assert_eq!(w.commit(), Err(Error::Permission { tid: g, needs: Role::Write }));
    let mut w = bob.write();
    w.at(g, osis::DynamicAspectKey::untyped(ak("app:sig.0*"))).set(&Value::Int(1)).unwrap();
    assert_eq!(w.commit(), Err(Error::Permission { tid: g, needs: Role::Write }));
    assert_eq!(durable_marks(&bob), before);
    let (_w, _alice, bob, g) = shared(Role::Write);
    let mut w = bob.write();
    let e = w.create_owned_by(g).unwrap();
    w.at(e, osis::DynamicAspectKey::untyped(ak("app:d.0~"))).set(&Value::Int(1)).unwrap();
    w.at(g, osis::DynamicAspectKey::untyped(ak("app:cursor.0~"))).set(&Value::Int(1)).unwrap();
    w.commit().unwrap();
    assert_eq!(bob.role_on(e).unwrap(), Some(Role::Write));
}

// notes/ephemeral.md Persistence: a role operation on a draft first persists it by its
// own commit; a durable reference to an ephemeral tid persists nothing (it may dangle).
// spec/data-model.md §1
#[test]
fn roles_persist_first_spec_data_model_1() {
    let (_w, alice, bob, g) = shared(Role::Read);
    let e = alice.commit_with(|w| w.create_owned_by(g)).unwrap();
    alice.grant(e, bob.me(), Role::Write, Default::default()).unwrap();
    assert!(alice.created(e).unwrap().unwrap().id.is_some(), "persisted first");
    assert!(alice.grants(e).unwrap().contains_key(&bob.me()));
    let (db, _c) = setup(20);
    let (d, e) = db
        .commit_with(|w| {
            let e = w.create()?;
            let d = w.create_durable(db.me())?;
            w.at(d, osis::DynamicAspectKey::untyped(ak("app:ref.0"))).set(&Value::Tid(e))?;
            Ok((d, e))
        })
        .unwrap();
    assert_eq!(db.created(e).unwrap().unwrap().id, None, "a reference persists nothing");
    assert!(db.created(d).unwrap().unwrap().id.is_some());
}

// notes/ephemeral.md API (Writes): an ephemeral op that fails when it resolves (a list
// index past the end) fails the whole commit: no commit, no new thing. Persisting a thing leaves
// the drafts it owns ephemeral; ephemeral memberships are written only through group
// ops (a raw `ephemeral_group.0~` write is Invalid).
// spec/data-model.md §1, §2
#[test]
fn mixed_commit_resolution_failure_and_partial_chain() {
    let (db, _c) = setup(21);
    let state = db.aspect_key("win:state.0~").unwrap();
    let before = durable_marks(&db);
    let mut w = db.write();
    let e = w.create().unwrap();
    w.at(db.me(), osis::DynamicAspectKey::untyped(ak("app:kept.0"))).set(&Value::Int(3)).unwrap();
    w.at(e, state.clone()).path(field(1)).splice(5..5, &[s("x")]).unwrap();
    assert!(w.commit().is_err());
    assert!(!db.has_content(e).unwrap());
    assert_eq!(durable_marks(&db), before);
    assert_eq!(db.at(db.me(), osis::DynamicAspectKey::untyped(ak("app:kept.0"))).get().unwrap(), None);
    let draft = ak("app:d.0~");
    let (p, c) = db
        .commit_with(|w| {
            let p = w.create()?;
            let c = w.create_owned_by(p)?;
            w.at(p, osis::DynamicAspectKey::untyped(ak("app:kept.0"))).set(&Value::Int(1))?;
            Ok((p, c))
        })
        .unwrap();
    db.commit_set(c, osis::DynamicAspectKey::untyped(draft.clone()), &Value::Int(1)).unwrap();
    assert!(db.created(p).unwrap().unwrap().id.is_some());
    assert_eq!(db.created(c).unwrap().unwrap().id, None);
    let n = db.engine(|e| e.commit_ids().len());
    db.commit_set(c, osis::DynamicAspectKey::untyped(ak("app:kept.0")), &Value::Int(2)).unwrap();
    assert_eq!(db.engine(|e| e.commit_ids().len()), n + 1);
    assert!(db.created(c).unwrap().unwrap().id.is_some());
    assert_eq!(db.at(c, osis::DynamicAspectKey::untyped(draft)).get().unwrap(), Some(Value::Int(1)));
    // `ephemeral_group.0~` is written by group ops only (`group.0`'s key is durable: no ephemeral raw write)
    let mut w = db.write();
    w.at(p, osis::DynamicAspectKey::untyped(ak("ephemeral_group.0~"))).set(&Value::Int(1)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(_))));
}

/// What `g` lists: its `group.0` and its ephemeral memberships (`ephemeral_group.0~`).
fn group_of(db: &Osis, g: osis::Tid) -> osis::internals::core_types::Group {
    let mut d = db.at(g, osis::internals::core_types::GROUP).get().unwrap().unwrap_or_default();
    let p = db.at(g, osis::internals::core_types::EPHEMERAL_GROUP).get().unwrap().unwrap_or_default();
    d.items.extend(p.items);
    d.subgroups.extend(p.subgroups);
    d
}

/// `g`'s `group.0` items (durable).
fn durable_items(db: &Osis, g: osis::Tid) -> Vec<osis::Tid> {
    db.at(g, osis::internals::core_types::GROUP).get().unwrap().unwrap_or_default().items.into_iter().collect()
}

// notes/ephemeral.md (`ephemeral_group.0~`): an ephemeral item added to a durable group is an
// ephemeral write of the group's `ephemeral_group.0~`: it lists there, in its `groups.0` and in a watch of
// `ephemeral_group.0~`, with no commit and no store write; removing it is ephemeral too.
// spec/data-model.md §8
#[test]
fn ephemeral_membership_lists_without_commit_spec_data_model_8() {
    let (db, _c) = setup(30);
    let home = db.me();
    let (tx, rx) = channel();
    let _sub = db.at(home, osis::internals::core_types::EPHEMERAL_GROUP).on_change(move |_, c| tx.send(c).unwrap()).unwrap();
    recv(&rx);
    let before = durable_marks(&db);
    let mut w = db.write();
    let t = w.create().unwrap();
    w.group(home).add(osis::Member::Item(t)).unwrap();
    let done = w.commit().unwrap().unwrap();
    assert!(done.id.commit().is_none());
    assert_eq!(durable_marks(&db), before, "no commit, no store write");
    assert!(group_of(&db, home).items.contains(&t));
    assert!(!durable_items(&db, home).contains(&t));
    assert!(db.groups_of(t).unwrap().within.contains(&home));
    assert_eq!(db.at(t, osis::internals::core_types::GROUPS).get().unwrap().map(|g| g.contains(&home)), Some(true));
    let ch = recv(&rx);
    assert!(matches!(ch.origin, Origin::Local(_)));
    assert!(ch.value.unwrap().unwrap().items.contains(&t));
    let mut w = db.write();
    w.group(home).remove(osis::Member::Item(t)).unwrap();
    w.commit().unwrap();
    assert_eq!(durable_marks(&db), before);
    assert!(!group_of(&db, home).items.contains(&t));
    assert!(db.groups_of(t).unwrap().within.is_empty());
}

// notes/ephemeral.md Persistence (`ephemeral_group.0~`): persisting a added draft
// writes its `created.0` and the durable `group.0` adds, an expiring one in a commit of its own
// (one expiry per commit), and the ephemeral element goes. spec/data-model.md §8, spec/commits.md
// §2, §6
#[test]
fn persisting_makes_memberships_durable_spec_data_model_8() {
    let (db, _c) = setup(31);
    let home = db.me();
    let saved = db.aspect_key("win:saved.0").unwrap();
    let (t, g) = db
        .commit_with(|w| {
            let g = w.create_durable(db.me())?;
            Ok((w.create()?, g))
        })
        .unwrap();
    db.commit_with(|w| w.group(home).add(osis::Member::Item(t))).unwrap();
    db.commit_with(|w| {
        w.expires(osis::Expiry::In(Duration::from_secs(3600)));
        w.group(g).add(osis::Member::Item(t))
    })
    .unwrap();
    // a membership that expires cannot be kept by the commit keeping its thing, whose record does not
    let n = db.engine(|e| e.commit_ids().len());
    let mut w = db.write();
    w.at(t, saved.clone()).set(&s("x")).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(m)) if m.contains("member of")));
    assert_eq!(db.engine(|e| e.commit_ids().len()), n, "nothing applied");
    assert_eq!(db.created(t).unwrap().unwrap().id, None);
    // out of it first; kept; then a durable membership that expires, in a commit of its own
    db.commit_with(|w| w.group(g).remove(osis::Member::Item(t))).unwrap();
    let done = commit_with(&db, |w| w.at(t, saved.clone()).set(&s("x")));
    assert_eq!(db.engine(|e| e.commit_ids().len()), n + 1, "one commit");
    let c = db.created(t).unwrap().unwrap().id.expect("persisted");
    assert_eq!(done.id, c);
    let h = db.engine(|e| e.header(&c.commit().unwrap())).unwrap();
    let entry = |tid: osis::Tid, a: &str| h.aspects.iter().find(|x| x.tid == tid && x.ak.as_str() == a).cloned();
    assert!(entry(t, "created.0").is_some() && entry(home, "group.0").is_some() && entry(g, "group.0").is_none());
    assert_eq!(h.expires, None);
    let x = commit_with(&db, |w| {
        w.expires(osis::Expiry::In(Duration::from_secs(3600)));
        w.group(g).add(osis::Member::Item(t))
    });
    let hx = db.engine(|e| e.header(&x.id.commit().unwrap())).unwrap();
    assert!(hx.aspects.iter().all(|a| a.tid == g && a.ak.as_str() == "group.0"));
    assert_eq!(hx.expires, Some(T0 + 3_600_000));
    assert!(durable_items(&db, home).contains(&t) && durable_items(&db, g).contains(&t));
    // the ephemeral side no longer names it: removing the durable element removes it
    let mut w = db.write();
    w.group(home).remove(osis::Member::Item(t)).unwrap();
    w.commit().unwrap();
    assert!(!group_of(&db, home).items.contains(&t));
    assert!(db.groups_of(t).unwrap().within.contains(&g) && !db.groups_of(t).unwrap().within.contains(&home));
    // a removal in the persisting commit wins over converting that membership
    let mut w = db.write();
    let u = w.create().unwrap();
    w.group(home).add(osis::Member::Item(u)).unwrap();
    w.commit().unwrap();
    let mut w = db.write();
    w.at(u, saved.clone()).set(&s("y")).unwrap();
    w.group(home).remove(osis::Member::Item(u)).unwrap();
    w.commit().unwrap();
    assert!(db.created(u).unwrap().unwrap().id.is_some());
    assert!(!group_of(&db, home).items.contains(&u) && !durable_items(&db, home).contains(&u));
}

// notes/ephemeral.md (`ephemeral_group.0~`): a draft added to a folder lands there at save
// (the save copies the draft's ephemeral content into a durable aspect).
// spec/data-model.md §1, §8
#[test]
fn draft_lands_in_folder_at_save_spec_data_model_8() {
    let (db, _c) = setup(32);
    let state = db.aspect_key("win:state.0~").unwrap();
    let saved = db.aspect_key("win:saved.0").unwrap();
    let mut w = db.write();
    let f = w.create_durable(db.me()).unwrap();
    w.group(db.me()).add(osis::Member::Item(f)).unwrap();
    w.group(db.me()).add(osis::Member::Subgroup(f)).unwrap();
    let folder = f;
    w.commit().unwrap();
    let mut w = db.write();
    let d = w.create().unwrap();
    w.group(folder).add(osis::Member::Item(d)).unwrap();
    w.at(d, state.clone()).set(&Value::Map([(Value::Int(0), s("title")), (Value::Int(1), Value::List(vec![s("body")]))].into())).unwrap();
    let draft = d;
    w.commit().unwrap();
    assert_eq!(db.groups_of(draft).unwrap().within.into_iter().collect::<std::collections::BTreeSet<_>>(), std::collections::BTreeSet::from([folder, db.me()]));
    assert!(durable_items(&db, folder).is_empty());
    db.commit_set(draft, saved.clone(), &s("title\nbody")).unwrap();
    assert!(db.created(draft).unwrap().unwrap().id.is_some());
    assert_eq!(durable_items(&db, folder), vec![draft]);
    assert_eq!(group_of(&db, folder).items.into_iter().collect::<Vec<_>>(), vec![draft]);
}

// notes/ephemeral.md (`ephemeral_group.0~`): a draft holding ephemeral memberships is a
// group already: another ephemeral item in a later commit neither clears `ephemeral_group.0~` nor persists
// the thing.
// spec/data-model.md §8
#[test]
fn adding_to_an_ephemeral_group_keeps_it_ephemeral_spec_data_model_8() {
    let (db, _c) = setup(37);
    let (g, t) = db
        .commit_with(|w| {
            let g = w.create()?;
            let t = w.create()?;
            w.group(g).add(osis::Member::Item(t))?;
            Ok((g, t))
        })
        .unwrap();
    assert!(group_of(&db, g).items.contains(&t));
    let u = db.commit_with(|w| { let u = w.create()?; w.group(g).add(osis::Member::Item(u))?; Ok(u) }).unwrap();
    assert!(group_of(&db, g).items.contains(&t) && group_of(&db, g).items.contains(&u), "its memberships kept");
    assert!(db.created(g).unwrap().unwrap().id.is_none(), "still ephemeral");
}

// notes/ephemeral.md Local engine (Restart, `ephemeral_group.0~`): a restart before persisting
// leaves no ghost: no durable group names the ephemeral tid, and it reads unknown.
// spec/data-model.md §8
#[test]
fn restart_leaves_no_dead_tids_in_groups_spec_data_model_8() {
    let dir = std::env::temp_dir().join(format!("osis-eph-place-{}-{:?}", std::process::id(), std::thread::current().id()).replace(['(', ')'], ""));
    let _ = std::fs::remove_dir_all(&dir);
    let c = clock();
    let at = |seed: u64| {
        let mut x = osis::internals::Opening::at(Store::Dir(dir.clone()));
        x.app.internals.seed = Some(seed);
        x.app.internals.clock = Some(c.clone());
        x
    };
    let db = osis::internals::create(at(1)).unwrap();
    let home = db.me();
    let g = db.commit_with(|w| w.create_durable(db.me())).unwrap();
    let (g, e, sub) = db
        .commit_with(|w| {
            let e = w.create()?;
            w.group(home).add(osis::Member::Item(e))?;
            w.group(g).add(osis::Member::Item(e))?;
            // an ephemeral subgroup of a durable group
            let sub = w.create()?;
            w.group(g).add(osis::Member::Subgroup(sub))?;
            Ok((g, e, sub))
        })
        .unwrap();
    assert!(group_of(&db, g).items.contains(&e) && group_of(&db, g).subgroups.contains(&sub));
    assert_eq!(db.close().unwrap(), osis::Close::Closed);
    let db = osis::internals::open(at(2)).unwrap();
    assert!(!db.has_content(e).unwrap() && !db.has_content(sub).unwrap());
    for x in [home, g] {
        let gr = group_of(&db, x);
        assert!(!gr.items.contains(&e) && !gr.subgroups.contains(&sub), "{x}");
        assert!(!durable_items(&db, x).contains(&e));
    }
    assert!(db.groups_of(e).unwrap().within.is_empty());
    assert_eq!(db.close().unwrap(), osis::Close::Closed);
    let _ = std::fs::remove_dir_all(&dir);
}

// notes/ephemeral.md (`ephemeral_group.0~`): a durable item added to an ephemeral group persists
// the group (and the group's own ephemeral memberships, and that it is a group); an ephemeral
// group of ephemeral items stays in memory, its remove persists nothing.
// spec/data-model.md §1, §8
#[test]
fn durable_item_persists_ephemeral_group_spec_data_model_8() {
    let (db, _c) = setup(33);
    let home = db.me();
    let before = durable_marks(&db);
    let (g, a, b) = db
        .commit_with(|w| {
            let g = w.create()?;
            w.group(home).add(osis::Member::Item(g))?;
            w.group(home).add(osis::Member::Subgroup(g))?;
            let a = w.create()?;
            let b = w.create()?;
            w.group(g).add(osis::Member::Item(a))?;
            w.group(g).add(osis::Member::Item(b))?;
            Ok((g, a, b))
        })
        .unwrap();
    assert_eq!(durable_marks(&db), before, "all ephemeral");
    assert!(db.groups_of(a).unwrap().within.contains(&g) && db.groups_of(a).unwrap().within.contains(&home));
    let mut w = db.write();
    w.group(g).remove(osis::Member::Item(b)).unwrap();
    w.commit().unwrap();
    assert_eq!(durable_marks(&db), before, "remove on an ephemeral group persists nothing");
    assert_eq!(db.created(g).unwrap().unwrap().id, None);
    let mut w = db.write();
    let d = w.create_durable(db.me()).unwrap();
    w.commit().unwrap();
    let mut w = db.write();
    w.group(g).add(osis::Member::Item(d)).unwrap();
    w.commit().unwrap();
    assert!(db.created(g).unwrap().unwrap().id.is_some(), "the group persisted");
    assert_eq!(durable_items(&db, g), vec![d]);
    assert!(durable_items(&db, home).contains(&g), "its membership too");
    assert!(group_of(&db, home).subgroups.contains(&g) && db.engine(|x| x.durable_groups_of(&d)).contains(&home), "and its subgroup entry");
    assert_eq!(db.created(a).unwrap().unwrap().id, None, "its ephemeral items stay ephemeral");
    assert!(group_of(&db, g).items.contains(&a));
    // a group persisted with no durable item keeps its (empty) durable `group.0`
    let mut w = db.write();
    let e = w.create().unwrap();
    let i = w.create().unwrap();
    w.group(e).add(osis::Member::Item(i)).unwrap();
    w.commit().unwrap();
    db.commit_set(e, osis::DynamicAspectKey::untyped(ak("app:kept.0")), &Value::Int(1)).unwrap();
    assert!(db.engine(|x| x.core.ix.by_aspect.get(&(e, ak("group.0"))).is_some_and(|s| !s.is_empty())));
}

// spec/permissions.md §1, notes/ephemeral.md (`ephemeral_group.0~`): persisting an item converts
// its ephemeral memberships, but only in groups the node may write: one added by a writer of a
// group this node only reads stays ephemeral there, reported once (`MembershipNotSaved`)
#[test]
fn membership_not_saved_without_write_on_group_spec_permissions_1() {
    let (mut w, alice, bob, g1, g2) = shared_two(Role::Write, Role::Read);
    let mut x = bob.write();
    let t = x.create_owned_by(g1).unwrap();
    x.group(g1).add(osis::Member::Item(t)).unwrap();
    x.commit().unwrap();
    w.run();
    // alice adds it to g2 too (ephemerally: t is ephemeral at alice, its record carried
    // under g1's label, whose reader t's record chain reaches)
    let mut x = alice.write();
    x.group(g2).add(osis::Member::Item(t)).unwrap();
    x.commit().unwrap();
    w.run();
    assert!(group_of(&bob, g2).items.contains(&t) && !durable_items(&bob, g2).contains(&t), "added ephemerally by alice");
    let (tx, rx) = channel();
    let _sub = bob.on_diagnostic(move |_, d| {
        if let osis::Diagnostic::MembershipNotSaved { item, group, .. } = d {
            let _ = tx.send(vec![item, group]);
        }
    }).unwrap();
    bob.commit_set(t, osis::DynamicAspectKey::untyped(ak("app:kept.0")), &Value::Int(1)).unwrap();
    assert!(bob.created(t).unwrap().unwrap().id.is_some());
    assert_eq!(recv(&rx), vec![t, g2]);
    assert!(group_of(&bob, g2).items.contains(&t), "still a member, ephemerally");
    assert!(!durable_items(&bob, g2).contains(&t));
    assert!(durable_items(&bob, g1).contains(&t), "the membership bob may write converted");
}

// notes/ephemeral.md (`ephemeral_group.0~`): persisting an item added with an expiry in an
// ephemeral group persists the group in the same commit whatever the tid order (its empty
// `group.0` takes the membership's expiry, which removes no value of it), and it stays a group
// after the membership expires. spec/crdt.md §4.7, spec/data-model.md §8
#[test]
fn expiring_membership_persists_ephemeral_group_spec_data_model_8() {
    for order in 0..4 {
        let (db, c) = setup(40 + order);
        let (g, x) = db
            .commit_with(|w| {
                let a = w.create()?;
                let b = w.create()?;
                let (g, x) = if (a < b) == (order % 2 == 0) { (a, b) } else { (b, a) };
                Ok((g, x))
            })
            .unwrap();
        let mut w = db.write();
        w.expires(osis::Expiry::In(Duration::from_secs(60)));
        w.group(g).add(osis::Member::Item(x)).unwrap();
        w.commit().unwrap();
        assert!(matches!(db.commit_set(x, osis::DynamicAspectKey::untyped(ak("app:kept.0")), &Value::Int(1)), Err(Error::Invalid(_))), "order {order}: its membership expires");
        db.commit_set(g, osis::DynamicAspectKey::untyped(ak("app:kept.0")), &Value::Int(1)).unwrap();
        assert!(db.created(g).unwrap().unwrap().id.is_some(), "order {order}");
        c.advance(120_000);
        db.engine(|e| e.tick().unwrap());
        assert_eq!(db.at(g, osis::internals::core_types::GROUP).get().unwrap(), Some(Default::default()), "order {order}: still a group");
    }
}

// notes/ephemeral.md Persistence: the persistence fixpoint through cycles (a group holding
// itself, two groups holding each other, an item owned by and added to an ephemeral group of
// that pair) persists every thing involved with its memberships, and a reopened store reads
// the same groups. spec/data-model.md §1, §8
#[test]
fn persistence_through_group_cycles_spec_data_model_8() {
    let dir = std::env::temp_dir().join(format!("osis-eph-cycles-{}-{:?}", std::process::id(), std::thread::current().id()).replace(['(', ')'], ""));
    let _ = std::fs::remove_dir_all(&dir);
    let c = clock();
    let at = |seed: u64| {
        let mut x = osis::internals::Opening::at(Store::Dir(dir.clone()));
        x.app.internals.seed = Some(seed);
        x.app.internals.clock = Some(c.clone());
        x
    };
    let db = osis::internals::create(at(1)).unwrap();
    let home = db.me();
    let (g, g1, g2, x) = db
        .commit_with(|w| {
            let g = w.create()?;
            w.group(g).add(osis::Member::Subgroup(g))?;
            w.group(g).add(osis::Member::Item(g))?;
            let g1 = w.create()?;
            let g2 = w.create_owned_by(g1)?;
            w.group(g1).add(osis::Member::Subgroup(g2))?;
            w.group(g2).add(osis::Member::Subgroup(g1))?;
            w.group(home).add(osis::Member::Subgroup(g1))?;
            let x = w.create_owned_by(g2)?;
            w.group(g2).add(osis::Member::Item(x))?;
            Ok((g, g1, g2, x))
        })
        .unwrap();
    assert!(db.groups_of(g).unwrap().within.contains(&g));
    assert!(db.groups_of(x).unwrap().within.contains(&g1) && db.groups_of(x).unwrap().within.contains(&home));
    db.commit_set(g, osis::DynamicAspectKey::untyped(ak("app:kept.0")), &Value::Int(1)).unwrap();
    db.commit_set(x, osis::DynamicAspectKey::untyped(ak("app:kept.0")), &Value::Int(2)).unwrap();
    for t in [g, g1, g2, x] {
        assert!(db.created(t).unwrap().unwrap().id.is_some(), "{t} persisted");
    }
    let check = |db: &Osis| {
        assert!(durable_items(db, g).contains(&g) && durable_items(db, g2).contains(&x));
        assert!(db.engine(|e| e.durable_groups_of(&x)).is_superset(&[g1, g2, home].into()));
        assert!(group_of(db, g1).subgroups.contains(&g2) && group_of(db, g2).subgroups.contains(&g1));
    };
    check(&db);
    assert_eq!(db.close().unwrap(), osis::Close::Closed);
    let db = osis::internals::open(at(2)).unwrap();
    check(&db);
    assert_eq!(db.close().unwrap(), osis::Close::Closed);
    let _ = std::fs::remove_dir_all(&dir);
}

// notes/ephemeral.md Persistence: a membership that does not convert (removed by the
// persisting commit) does not persist its ephemeral group. spec/data-model.md §8
#[test]
fn removed_membership_does_not_persist_its_group_spec_data_model_8() {
    let (db, _c) = setup(45);
    let (g, x) = db
        .commit_with(|w| {
            let g = w.create()?;
            let x = w.create()?;
            w.group(g).add(osis::Member::Item(x))?;
            Ok((g, x))
        })
        .unwrap();
    let mut w = db.write();
    w.at(x, osis::DynamicAspectKey::untyped(ak("app:kept.0"))).set(&Value::Int(1)).unwrap();
    w.group(g).remove(osis::Member::Item(x)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(_))), "g stays ephemeral: a removal there is an ephemeral write");
    db.commit_with(|w| w.group(g).remove(osis::Member::Item(x))).unwrap();
    db.commit_set(x, osis::DynamicAspectKey::untyped(ak("app:kept.0")), &Value::Int(1)).unwrap();
    assert!(db.created(x).unwrap().unwrap().id.is_some());
    assert_eq!(db.created(g).unwrap().unwrap().id, None);
    assert!(!group_of(&db, g).items.contains(&x));
}

// spec/permissions.md §4: a memory commit acting for the account counts among the actors this
// node acts for (its chain certificates go under every label it places in): the actors cache
// keyed on the durable generation alone missed it, and the sync driver's check of it died
#[test]
fn ephemeral_write_counts_as_acting_spec_permissions_4() {
    let (db, _c) = setup(1);
    let state = db.aspect_key("win:state.0~").unwrap();
    let before = db.engine(|e| e.core.acting());
    assert!(!before.contains(&db.me()), "nothing acted for the account yet: {before:?}");
    let mut w = db.write();
    let win = w.create().unwrap();
    w.at(win, state.clone()).set(&Value::Map([(Value::Int(0), s("draft")), (Value::Int(1), Value::List(vec![]))].into())).unwrap();
    w.commit().unwrap();
    let after = db.engine(|e| e.core.acting());
    assert!(after.contains(&db.me()), "{after:?}");
}

// spec/commits.md §6, notes/api.md Writes: a disappearing thing end to end. The commit expiring cannot
// keep the thing, and says how; the first commit holds no value when it removes an aspect; the
// expiring one then writes and places it, undo and redo work, and at T only the record is left.
#[test]
fn a_thing_with_only_expiring_content_spec_commits_6() {
    let (db, c) = setup(40);
    let (body, hour) = (osis::DynamicAspectKey::untyped(ak("app:body.0")), Duration::from_secs(3600));
    let g = db.commit_with(|w| {
        let g = w.create()?;
        w.at(g, osis::DynamicAspectKey::untyped(ak("app:kept.0"))).set(&Value::Int(1))?;
        Ok(g)
    })
    .unwrap();
    let mut w = db.write();
    w.expires(osis::Expiry::In(hour));
    let lost = w.create().unwrap();
    w.at(lost, body.clone()).set(&s("x")).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(m)) if m.contains("removing an aspect") && m.contains(&lost.to_string())));
    let mut w = db.write();
    let t = w.create().unwrap();
    w.at(t, body.clone()).remove().unwrap();
    let kept = w.commit().unwrap().unwrap();
    let h = db.engine(|e| e.header(&kept.id.commit().unwrap())).unwrap();
    assert_eq!(h.aspects.iter().map(|a| a.ak.as_str().to_string()).collect::<Vec<_>>(), ["created.0", "app:body.0"], "the record, and a reset holding no value");
    assert_eq!(h.expires, None);
    let mut w = db.write();
    w.expires(osis::Expiry::In(hour));
    w.at(t, body.clone()).set(&s("x")).unwrap();
    w.group(g).add(osis::Member::Item(t)).unwrap();
    let msg = w.commit().unwrap().unwrap();
    assert_eq!(db.engine(|e| e.header(&msg.id.commit().unwrap())).unwrap().expires, Some(T0 + 3_600_000));
    let scope = osis::Scope::Thing(t);
    db.undo(&scope).unwrap().unwrap();
    assert_eq!(db.at(t, body.clone()).get().unwrap(), None);
    db.redo(&scope).unwrap().unwrap();
    assert_eq!(db.at(t, body.clone()).get().unwrap(), Some(s("x")));
    assert!(durable_items(&db, g).contains(&t));
    c.advance(3_700_000);
    db.engine(|e| e.tick().unwrap());
    assert_eq!(db.at(t, body).get().unwrap(), None);
    assert!(!durable_items(&db, g).contains(&t), "out of its group");
}
