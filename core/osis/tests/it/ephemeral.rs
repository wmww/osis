//! Local ephemeral aspects (notes/ephemeral.md): in memory, no durable commit, no store write;
//! restart forgets; rights as for durable writes; expiry in memory; signal aspects.

use osis::internals::Exact as _;
use osis::internals::CommitRaw as _;
use crate::common::watched;
use crate::common::TestWrites as _;
use osis::internals::Internals as _;
use crate::common::*;
use osis_sim::world::World;
use osis::{Error, MemStore, Osis, Role, Origin, Store, Value};
use std::sync::mpsc::channel;
use std::time::Duration;

const SCHEMA: &str = "revision 1;\n\
type win = struct { title 0: string, notes 1: list<string> };\n\
ephemeral aspect win:state+.0: win;\n\
expires(5s) ephemeral aspect win:typing+.0: bool;\n\
expires(30s) ephemeral aspect win:cursor+.0: map<tid, int>;\n\
ephemeral signal win:ring+~0: string;\n\
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

// notes/ephemeral.md Model, Local engine: ephemeral aspects (typed, with path ops) are written,
// read and watched with no durable commit and no store write. spec/data-model.md §2
#[test]
fn write_and_watch_without_commit_spec_data_model_2() {
    let (db, _c) = setup(1);
    let state = db.aspect_key("win:state+.0").unwrap();
    let made = commit_with(&db, |w| w.create().map(drop));
    let win = db.engine(|e| e.header(&made.stamp.id.raw())).unwrap().aspects[0].tid;
    let c = db.created(win).unwrap().unwrap();
    // a record alone acts for its signer (spec/commits.md §2)
    assert_eq!((c.id, c.ts(), c.node, c.actor), (made.stamp.id, made.ts(), db.node(), db.node()), "a new thing is durable");
    let before = durable_marks(&db);
    let mut w = db.write();
    w.at(win, state.clone()).set(&Value::Map([(Value::Int(0), s("draft")), (Value::Int(1), Value::List(vec![s("a")]))].into())).unwrap();
    let done = w.commit().unwrap().unwrap();
    assert!(db.engine(|e| e.holds_memory(&done.stamp.id.raw())), "an ephemeral commit, in memory");
    assert_eq!(durable_marks(&db), before, "no commit, no store write");
    assert!(db.has_content(win).unwrap());
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
        Origin::Local(i) => assert_eq!((i.id, i.ts(), i.node), (done.stamp.id, done.ts(), db.node())),
        other => panic!("{other:?}"),
    }
    assert_eq!(db.at(win, state.clone()).path(field(1)).get::<Vec<String>>().unwrap(), Some(vec!["a".to_string(), "b".to_string()]));
    assert!(watch.changed_timeout(Duration::from_secs(20)));
    assert!(watch.current().unwrap().is_some());
    assert_eq!(db.aspects(win).unwrap(), vec![osis::Ak::new("created.0").unwrap(), osis::Ak::new("win:state+.0").unwrap()]);
    // an ephemeral aspect of a durable thing
    let cur = ak("app:selection+.0");
    db.commit_set(db.me(), osis::DynamicAspectKey::untyped(cur.clone()), &Value::Int(7)).unwrap();
    assert_eq!(db.at(db.me(), osis::DynamicAspectKey::untyped(cur)).get().unwrap(), Some(Value::Int(7)));
    assert_eq!(durable_marks(&db), before);
    assert!(db.aspects(db.me()).unwrap().contains(&ak("app:selection+.0")));
}

// notes/ephemeral.md Local engine (Restart): on a `Dir` store, reopening forgets every
// ephemeral aspect; durable data is intact. spec/requirements.md (data model: ephemeral state in
// memory)
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
    let draft = ak("app:draft+.0");
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

// notes/ephemeral.md Rights: a node with no write on a thing can neither create one under it
// nor write ephemeral data on it; a new thing's role is its first admin's. spec/permissions.md §1
#[test]
fn rights_through_first_admin_spec_permissions_1() {
    let (a, _c) = setup(3);
    let (b, _c2) = setup(4);
    let mut w = a.write();
    let t = w.create().unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(ak("app:kept.0"))).set(&Value::Int(1)).unwrap();
    w.commit().unwrap();
    deliver(&a, &b);
    assert_eq!(b.role_on(t).unwrap(), None);
    let before = durable_marks(&b);
    // a thing under another actor's thing
    let mut w = b.write();
    w.create_with_admin(t).unwrap();
    assert!(matches!(w.commit(), Err(Error::Permission { .. })));
    // ephemeral data on another actor's durable thing
    let mut w = b.write();
    w.at(t, osis::DynamicAspectKey::untyped(ak("app:cursor+.0"))).set(&Value::Int(1)).unwrap();
    assert_eq!(w.commit(), Err(Error::Permission { tid: t, needs: Role::Write }));
    assert_eq!(b.at(t, osis::DynamicAspectKey::untyped(ak("app:cursor+.0"))).get().unwrap(), None);
    assert_eq!(durable_marks(&b), before);
    // a's own chain under t: admin through t
    let (x, y) = a
        .commit_with(|w| {
            let x = w.create_with_admin(t)?;
            let y = w.create_with_admin(x)?;
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
    let typing = db.aspect_key("win:typing+.0").unwrap();
    let note = ak("app:note+.0");
    let t = db.commit_with(|w| w.create()).unwrap();
    let mut w = db.write();
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
    w.at(t, osis::DynamicAspectKey::untyped(ak("app:x+.0"))).set(&Value::Int(1)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(_))));
}

// spec/data-model.md §2 (signal), spec/sync.md §9: each fire of an ephemeral signal reaches the
// aspect's history listener once, as it was fired, and nothing else: no page shows it (nobody holds
// it), reads and value watches stay absent; any other op is Invalid
#[test]
fn ephemeral_signal_fires_reach_history_listener_once_spec_data_model_2() {
    let (db, _c) = setup(6);
    let ring = db.aspect_key("win:ring+~0").unwrap();
    let mut w = db.write();
    let t = w.create().unwrap();
    w.commit().unwrap();
    let (tx, rx) = channel();
    let _sub = db.at(t, ring.clone()).on_change(move |_, c| tx.send(c).unwrap()).unwrap();
    assert_eq!(recv(&rx).value, Ok(None));
    let (ttx, trx) = channel();
    let _th = db.on_thing_change(t, move |_, c| ttx.send(c).unwrap()).unwrap();
    let (htx, hrx) = channel();
    let _h = db.at(t, ring.clone()).on_fire(move |_, e| htx.send(e).unwrap()).unwrap();
    // the thing's initial reads (its `created.0`)
    db.settle();
    while trx.try_recv().is_ok() {}
    let before = durable_marks(&db);
    let mut ids = Vec::new();
    for _ in 0..2 {
        let mut w = db.write();
        w.at(t, ring.clone()).fire(&s("ding")).unwrap();
        ids.push(w.commit().unwrap().unwrap().stamp.id);
    }
    for id in &ids {
        match recv(&hrx) {
            osis::CommitEvent::Commit { id: i, commit: Some(c) } => {
                assert_eq!(i, *id);
                assert_eq!(c.stamp.id, *id);
                let p = c.at(t, ring.clone()).unwrap();
                assert_eq!((c.stamp.actor, c.stamp.node, c.kind, p.valid), (db.me(), db.node(), osis::CommitKind::Content, true));
                assert_eq!(p.body, osis::Body::Held(Some(s("ding"))));
            }
            e => panic!("{e:?}"),
        }
    }
    db.settle();
    assert!(hrx.try_recv().is_err(), "once each");
    assert!(rx.try_recv().is_err(), "on_change hears nothing");
    assert!(trx.try_recv().is_err(), "on_thing_change hears nothing");
    assert!(db.at(t, ring.clone()).fired(&page(osis::CommitFrom::Newest, 10)).unwrap().commits.is_empty(), "nobody holds it");
    assert_eq!(db.at(t, ring.clone()).get().unwrap(), None, "a signal holds nothing");
    assert!(!db.aspects(t).unwrap().contains(&ak("win:ring+~0")));
    assert_eq!(durable_marks(&db), before);
    let mut w = db.write();
    w.at(t, ring.clone()).remove().unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(_))));
    let mut w = db.write();
    w.at(t, osis::DynamicAspectKey::untyped(ak("app:sig+~0"))).path(osis::p!["k"]).set(&Value::Int(1)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(_))));
}

// spec/data-model.md §2, spec/commits.md §5 Signals: a signal without `+` reads absent and each
// write is a commit kept in history, heard through `on_fire` alone (`on_change` sees nothing);
// a schema gives it keep_history, and a revert writes nothing back for it
#[test]
fn signal_without_ephemeral_is_history_spec_commits_5() {
    let (db, _c) = setup(9);
    db.register_schema("log.osis", "revision 1;\nkeep_history(30d) signal app:log~0: string;\n").unwrap();
    let e = db.register_schema("bad.osis", "revision 1;\nsignal app:bad~0: int;\n").unwrap_err();
    assert!(e.to_string().contains("a signal declares keep_history"), "{e}");
    let log = db.aspect_key("app:log~0").unwrap();
    let t = db.commit_with(|w| w.create()).unwrap();
    let (tx, rx) = channel();
    let _sub = db.at(t, log.clone()).on_change(move |_, c| tx.send(c).unwrap()).unwrap();
    assert_eq!(recv(&rx).value, Ok(None));
    let (htx, hrx) = channel();
    let key = log.clone();
    let _hsub = db
        .at(t, log.clone())
        .on_fire(move |_, ev| {
            if let osis::CommitEvent::Commit { commit: Some(c), .. } = ev {
                htx.send(c.at(t, key.clone()).unwrap().body).unwrap();
            }
        })
        .unwrap();
    db.commit_fire(t, log.clone(), &s("hi")).unwrap();
    db.commit_fire(t, log.clone(), &s("yo")).unwrap();
    assert_eq!(recv(&hrx), osis::Body::Held(Some(s("hi"))));
    assert_eq!(recv(&hrx), osis::Body::Held(Some(s("yo"))));
    db.settle();
    assert!(hrx.try_recv().is_err(), "once each");
    assert!(rx.try_recv().is_err(), "on_change sees nothing");
    assert_eq!(db.at(t, log.clone()).get().unwrap(), None);
    let got = db.at(t, log.clone()).fired(&page(osis::CommitFrom::Oldest, 10)).unwrap();
    let bodies: Vec<_> = got.commits.iter().map(|c| c.at(t, log.clone()).unwrap().body).collect();
    assert_eq!(bodies, vec![osis::Body::Held(Some(s("hi"))), osis::Body::Held(Some(s("yo")))]);
    assert!(db.at(t, log.clone()).writes(&osis::CommitQuery::default()).unwrap().commits.is_empty(), "a signal lists no writes");
    assert!(matches!(db.revert(got.commits[0].stamp.id), Err(Error::NotUndoable { reason: osis::NotUndoableReason::Superseded, .. })));
}

// spec/data-model.md §2 (signal), notes/api.md Keys: a dynamic key takes both kinds' calls, its kind known
// only at run time: a write of the other kind (a value write on a signal, a fire on a value aspect)
// fails `commit` with `Invalid` and writes nothing, a read of the other kind finds nothing
#[test]
fn dynamic_key_crossing_kinds_spec_data_model_2() {
    let (db, _c) = setup(10);
    db.register_schema("k.osis", "revision 1;\nkeep_history(30d) signal app:log~0: string;\naspect app:n.0: string;\n").unwrap();
    let (log, n) = (db.aspect_key("app:log~0").unwrap(), db.aspect_key("app:n.0").unwrap());
    let t = db.commit_with(|w| w.create()).unwrap();
    let refused = |f: &dyn Fn(&mut osis::Write<'_>) -> osis::Result<()>, word: &str| {
        let mut w = db.write();
        f(&mut w).unwrap();
        assert!(matches!(w.commit(), Err(Error::Invalid(m)) if m.contains(word)), "{word}");
    };
    refused(&|w| w.at(t, log.clone()).set(&s("x")), "fire");
    refused(&|w| w.at(t, log.clone()).overwrite(&s("x")), "fire");
    refused(&|w| w.at(t, log.clone()).remove(), "fire");
    refused(&|w| w.at(t, n.clone()).fire(&s("x")), "set");
    refused(&|w| w.at(t, osis::DynamicAspectKey::untyped(ak("app:raw+~0"))).set(&s("x")), "fire");
    refused(&|w| w.at(t, osis::DynamicAspectKey::untyped(ak("app:raw+.0"))).fire(&s("x")), "set");
    assert_eq!(db.at(t, n.clone()).get().unwrap(), None, "nothing written");
    assert!(db.at(t, log.clone()).fired(&osis::CommitQuery::default()).unwrap().commits.is_empty(), "nothing fired");
    db.commit_set(t, n.clone(), &s("v")).unwrap();
    db.commit_fire(t, log.clone(), &s("f")).unwrap();
    assert_eq!(db.at(t, log.clone()).get().unwrap(), None, "a signal reads absent");
    assert!(db.at(t, log.clone()).writes(&osis::CommitQuery::default()).unwrap().commits.is_empty(), "a signal lists no writes");
    assert!(db.at(t, n.clone()).fired(&osis::CommitQuery::default()).unwrap().commits.is_empty(), "a value aspect lists no fires");
    assert_eq!(db.at(t, log.clone()).fired(&osis::CommitQuery::default()).unwrap().commits.len(), 1);
    assert_eq!(db.at(t, n).get().unwrap(), Some(s("v")));
    // a purge of a signal's whole history takes its fires (it has no value to remove)
    db.commit_with(|w| w.at(t, log.clone()).purge(osis::Purge::All)).unwrap();
    let left = db.at(t, log.clone()).fired(&osis::CommitQuery::default()).unwrap().commits;
    assert!(left.iter().all(|c| !matches!(c.at(t, log.clone()).map(|p| p.body), Some(osis::Body::Held(_)))), "{left:?}");
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
    let draft = ak("app:draft+.0");
    let kept = ak("app:kept.0");
    let mut w = b.write();
    let e = w.create().unwrap();
    w.at(b.me(), osis::DynamicAspectKey::untyped(draft.clone())).set(&Value::Int(1)).unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(kept.clone())).set(&Value::Int(2)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(m)) if m.contains("app:draft+.0") && m.contains("app:kept.0")));
    assert!(!b.has_content(e).unwrap());
    assert_eq!(b.at(b.me(), osis::DynamicAspectKey::untyped(draft.clone())).get().unwrap(), None);
    // an ephemeral op takes no retention
    let before = durable_marks(&b);
    let mut w = b.write();
    w.at(b.me(), osis::DynamicAspectKey::untyped(draft.clone())).retention(osis::Retention::default()).set(&Value::Int(1)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(_))));
    assert_eq!(durable_marks(&b), before);
    // nor an ephemeral write on a thing the write creates: its record is durable
    let mut w = b.write();
    let x = w.create().unwrap();
    w.at(x, osis::DynamicAspectKey::untyped(draft.clone())).set(&Value::Int(1)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(m)) if m.contains("app:draft+.0") && m.contains(&format!("the creation of {x}"))));
    assert!(b.created(x).unwrap().is_none());
    // nor a signal beside an ephemeral write
    let mut w = b.write();
    w.at(b.me(), osis::DynamicAspectKey::untyped(ak("app:ring+~0"))).fire(&Value::Int(1)).unwrap();
    w.at(b.me(), osis::DynamicAspectKey::untyped(draft.clone())).set(&Value::Int(1)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(m)) if m.contains("signal")));
    // nor ephemeral writes of two expiries
    b.register_schema("cursor.osis", "revision 1;\nexpires(30s) ephemeral aspect app:cursor+.0: int;").unwrap();
    let mut w = b.write();
    w.at(b.me(), b.aspect_key("app:cursor+.0").unwrap()).set(&Value::Int(1)).unwrap();
    w.at(b.me(), osis::DynamicAspectKey::untyped(draft.clone())).set(&Value::Int(1)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(m)) if m.contains("one expiry")));
    assert_eq!(durable_marks(&b), before, "nothing applied");
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
    assert!(matches!(w.commit(), Err(Error::Invalid(m)) if m.contains("app:draft+.0") && m.contains("app:kept.0")));
    let mut w = b.write();
    w.delete(gone).unwrap();
    w.at(gone, osis::DynamicAspectKey::untyped(ak("app:ring+~0"))).fire(&Value::Int(1)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(m)) if m.contains("app:ring+~0")));
    assert_eq!((durable_marks(&b), b.has_content(gone).unwrap()), (marks, true), "nothing applied");
    // apart: the durable one a commit, the ephemeral one with an id of its own, each what its watch names
    let (tx, rx) = channel();
    let _sub = b.at(b.me(), osis::DynamicAspectKey::untyped(draft.clone())).on_change(move |_, c| tx.send(c).unwrap()).unwrap();
    recv(&rx);
    let done = commit_with(&b, |w| w.at(b.me(), osis::DynamicAspectKey::untyped(kept.clone())).set(&Value::Int(3)));
    let c = done.stamp.id.raw();
    assert_eq!(b.engine(|e| e.header(&c)).unwrap().ts, done.ts());
    let own = commit_with(&b, |w| w.at(b.me(), osis::DynamicAspectKey::untyped(draft.clone())).set(&Value::Int(4)));
    assert!(b.engine(|e| e.holds_memory(&own.stamp.id.raw())));
    assert_ne!(own.stamp.id, done.stamp.id);
    match recv(&rx).origin {
        Origin::Local(i) => assert_eq!((i.id, i.ts()), (own.stamp.id, own.ts())),
        other => panic!("{other:?}"),
    }
    // a new thing with only an expiring durable write is refused: its record does not expire
    let mut w = b.write();
    let x = w.create().unwrap();
    w.expires(osis::Expiry::In(Duration::from_secs(5)));
    w.at(x, osis::DynamicAspectKey::untyped(kept.clone())).set(&Value::Int(1)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(m)) if m.contains("record")));
    assert!(!b.has_content(x).unwrap());
}

// notes/ephemeral.md Deletion: deleting a thing ends its ephemeral aspects here too and takes it
// out of its groups, in one durable commit: no memory commit is written. spec/data-model.md §1,
// spec/commits.md §2
#[test]
fn delete_resets_ephemeral_aspects_spec_data_model_1() {
    let (db, _c) = setup(9);
    let draft = ak("app:draft+.0");
    let x = db
        .commit_with(|w| {
            let x = w.create()?;
            w.group(db.me()).add(osis::Member::Item(x))?;
            Ok(x)
        })
        .unwrap();
    db.commit_set(x, osis::DynamicAspectKey::untyped(draft.clone()), &Value::Int(1)).unwrap();
    let (tx, rx) = channel();
    let _sub = db.at(x, osis::DynamicAspectKey::untyped(draft.clone())).on_change(move |_, c| tx.send(c).unwrap()).unwrap();
    recv(&rx);
    let memory = |db: &Osis| db.engine(|e| e.memory_commits().into_iter().map(|(c, _, _)| c).collect::<std::collections::BTreeSet<_>>());
    let held = memory(&db);
    let mut w = db.write();
    w.delete(x).unwrap();
    let c = w.commit().unwrap().unwrap().stamp.id.raw();
    assert!(!db.engine(|e| e.holds_memory(&c)));
    assert!(memory(&db).is_subset(&held), "no memory commit written");
    assert_eq!(recv(&rx).value, Ok(None));
    assert!(!db.has_content(x).unwrap());
    assert!(!group_of(&db, db.me()).items.contains(&x), "its membership goes with it");
}

/// Alice's synced group `g` with Bob granted `role` on it, through one host.
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
// only read): a reader of a thing can neither create a thing under it, write an ephemeral aspect
// on it nor fire a signal there; a writer can.
// spec/permissions.md §1
#[test]
fn reader_cannot_write_ephemeral_spec_permissions_1() {
    let (_w, _alice, bob, g) = shared(Role::Read);
    assert_eq!(bob.role_on(g).unwrap(), Some(Role::Read));
    let before = durable_marks(&bob);
    let mut w = bob.write();
    w.create_with_admin(g).unwrap();
    assert!(matches!(w.commit(), Err(Error::Permission { .. })), "a reader creates under g");
    let mut w = bob.write();
    w.at(g, osis::DynamicAspectKey::untyped(ak("app:cursor+.0"))).set(&Value::Int(1)).unwrap();
    assert_eq!(w.commit(), Err(Error::Permission { tid: g, needs: Role::Write }));
    let mut w = bob.write();
    w.at(g, osis::DynamicAspectKey::untyped(ak("app:sig+~0"))).fire(&Value::Int(1)).unwrap();
    assert_eq!(w.commit(), Err(Error::Permission { tid: g, needs: Role::Write }));
    assert_eq!(durable_marks(&bob), before);
    let (_w, _alice, bob, g) = shared(Role::Write);
    let e = bob.commit_with(|w| w.create_with_admin(g)).unwrap();
    let mut w = bob.write();
    w.at(e, osis::DynamicAspectKey::untyped(ak("app:d+.0"))).set(&Value::Int(1)).unwrap();
    w.at(g, osis::DynamicAspectKey::untyped(ak("app:cursor+.0"))).set(&Value::Int(1)).unwrap();
    w.commit().unwrap();
    assert_eq!(bob.role_on(e).unwrap(), Some(Role::Write));
}

// notes/ephemeral.md API (Writes): an ephemeral op that fails when it resolves (a list index
// past the end) fails the whole commit: nothing of it applies. spec/data-model.md §2
#[test]
fn failed_ephemeral_op_fails_the_commit_spec_data_model_2() {
    let (db, _c) = setup(21);
    let state = db.aspect_key("win:state+.0").unwrap();
    let e = db.commit_with(|w| w.create()).unwrap();
    let mut w = db.write();
    w.at(db.me(), osis::DynamicAspectKey::untyped(ak("app:kept+.0"))).set(&Value::Int(3)).unwrap();
    w.at(e, state.clone()).path(field(1)).splice(5..5, &[s("x")]).unwrap();
    assert!(w.commit().is_err());
    assert_eq!(db.at(db.me(), osis::DynamicAspectKey::untyped(ak("app:kept+.0"))).get().unwrap(), None);
    assert_eq!(db.at(e, state).get().unwrap(), None);
}

/// What `g` lists: its `group.0`.
fn group_of(db: &Osis, g: osis::Tid) -> osis::internals::core_types::Group {
    db.at(g, osis::internals::core_types::GROUP).get().unwrap().unwrap_or_default()
}

/// `g`'s `group.0` items.
fn durable_items(db: &Osis, g: osis::Tid) -> Vec<osis::Tid> {
    group_of(db, g).items.into_iter().collect()
}

// spec/permissions.md §4: a memory commit acting for the account counts among the actors this
// node acts for (its chain certificates go under every label it places in): the actors cache
// keyed on the durable generation alone missed it, and the sync driver's check of it died
#[test]
fn ephemeral_write_counts_as_acting_spec_permissions_4() {
    let (db, _c) = setup(1);
    let state = db.aspect_key("win:state+.0").unwrap();
    let before = db.engine(|e| e.core.acting());
    assert!(!before.contains(&db.me()), "nothing acted for the account yet: {before:?}");
    // a record alone acts for its signer (spec/commits.md §2)
    let win = db.commit_with(|w| w.create()).unwrap();
    assert!(!db.engine(|e| e.core.acting()).contains(&db.me()), "a record alone acts for the node");
    let mut w = db.write();
    w.at(win, state.clone()).set(&Value::Map([(Value::Int(0), s("draft")), (Value::Int(1), Value::List(vec![]))].into())).unwrap();
    w.commit().unwrap();
    let after = db.engine(|e| e.core.acting());
    assert!(after.contains(&db.me()), "{after:?}");
}

// spec/commits.md §6, notes/api.md Writes: a disappearing thing end to end. The commit expiring cannot
// create the thing, and says how; the commit creating it holds its record alone; the expiring one
// then writes and places it, undo and redo work (the body and `group.0` keep history), and at T
// only the record is left.
#[test]
fn a_thing_with_only_expiring_content_spec_commits_6() {
    let (db, c) = setup(40);
    keep_day(&db, &["app:body.0"]);
    let (body, hour) = (kept(&db, &ak("app:body.0")), Duration::from_secs(3600));
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
    assert!(matches!(w.commit(), Err(Error::Invalid(m)) if m.contains("commit of its own") && m.contains(&lost.to_string())));
    let mut w = db.write();
    let t = w.create().unwrap();
    let kept = w.commit().unwrap().unwrap();
    let h = db.engine(|e| e.header(&kept.stamp.id.raw())).unwrap();
    assert_eq!(h.aspects.iter().map(|a| a.ak.as_str().to_string()).collect::<Vec<_>>(), ["created.0"], "the record alone");
    assert_eq!(h.expires, None);
    let mut w = db.write();
    w.expires(osis::Expiry::In(hour));
    w.at(t, body.clone()).set(&s("x")).unwrap();
    w.group(g).add(osis::Member::Item(t)).unwrap();
    let msg = w.commit().unwrap().unwrap();
    assert_eq!(db.engine(|e| e.header(&msg.stamp.id.raw())).unwrap().expires, Some(T0 + 3_600_000));
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
