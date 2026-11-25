//! Local ephemeral aspects (notes/ephemeral.md): in memory, no durable commit, no store write;
//! restart forgets; rights as for durable writes; expiry in memory; signal aspects.

use osis::internals::Exact as _;
use osis::internals::CommitRaw as _;
use osis::internals::Internals as _;
use crate::common::*;
use osis::{Error, MemStore, Osis, Role, Origin, Store, Value};
use std::sync::mpsc::channel;
use std::time::Duration;

const SCHEMA: &str = "revision 1;\n\
type win = struct { title 0: string, notes 1: list<string> };\n\
ephemeral aspect win:state+.0: win;\n\
expires(5s) ephemeral aspect win:typing+.0: bool;\n\
expires(30s) ephemeral aspect win:cursor+.0: map<weak, int>;\n\
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

// notes/ephemeral.md Model, Local engine: ephemeral aspects (typed, with path ops) are written,
// read and watched with no durable commit and no store write. spec/data-model.md §2
#[test]
fn write_and_watch_without_commit_spec_data_model_2() {
    let (db, _c) = setup(0);
    let state = db.aspect_key("win:state+.0").unwrap();
    let made = commit_with(&db, |w| w.create_held_with_admin(crate::common::home(&db)).map(drop));
    let win = db.engine(|e| e.header(&made.stamp.id.raw())).unwrap().aspects.iter().find(|a| a.ak.as_str() == "created.0").unwrap().tid;
    let c = db.created(win).unwrap().unwrap();
    // a record alone acts for its signer (spec/commits.md §2)
    assert_eq!((c.id, c.ts(), c.author), (made.stamp.id, made.ts(), db.author()), "a new thing is durable");
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
        Origin::Local(i) => assert_eq!((i.id, i.ts(), i.author), (done.stamp.id, done.ts(), db.author())),
        other => panic!("{other:?}"),
    }
    assert_eq!(db.at(win, state.clone()).path(field(1)).get::<Vec<String>>().unwrap(), Some(vec!["a".to_string(), "b".to_string()]));
    assert!(watch.changed_timeout(Duration::from_secs(20)));
    assert!(watch.current().unwrap().is_some());
    assert_eq!(db.aspects(win).unwrap(), vec![osis::Ak::new("created.0").unwrap(), osis::Ak::new("win:state+.0").unwrap()]);
    // an ephemeral aspect of a durable thing
    let cur = ak("app:selection+.0");
    db.commit_set(db.author(), osis::DynamicAspectKey::untyped(cur.clone()), &Value::Int(7)).unwrap();
    assert_eq!(db.at(db.author(), osis::DynamicAspectKey::untyped(cur)).get().unwrap(), Some(Value::Int(7)));
    assert_eq!(durable_marks(&db), before);
    assert!(db.aspects(db.author()).unwrap().contains(&ak("app:selection+.0")));
}

// notes/ephemeral.md Restarts and lost access: on a `Dir` store, reopening forgets every
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
            let d = w.create_held()?;
            w.at(d, untyped("app:kept.0")).set(&Value::Int(1))?;
            let e = w.create_held()?;
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
    assert_eq!(db.at(d, untyped("app:kept.0")).get().unwrap(), Some(Value::Int(1)));
    assert_eq!(db.at(d, osis::DynamicAspectKey::untyped(draft)).get().unwrap(), None);
    assert_eq!(db.close().unwrap(), osis::Close::Closed);
    let _ = std::fs::remove_dir_all(&dir);
}

// notes/ephemeral.md Rights: a node with no write on a thing can neither mint one with it as admin
// nor write ephemeral data on it; a new thing's role is its mint admin's. spec/permissions.md §1
#[test]
fn rights_through_mint_admin_spec_permissions_1() {
    let (a, _c) = setup(3);
    let (b, _c2) = setup(4);
    let mut w = a.write();
    let t = w.create_held().unwrap();
    w.at(t, untyped("app:kept.0")).set(&Value::Int(1)).unwrap();
    w.commit().unwrap();
    deliver(&a, &b);
    assert_eq!(b.role_on(t).unwrap(), None);
    let before = durable_marks(&b);
    // a thing minted with another actor's thing as admin
    let mut w = b.write();
    w.create_held_with_admin(t).unwrap();
    assert!(matches!(w.commit(), Err(Error::Permission { .. })));
    // ephemeral data on another actor's durable thing
    let mut w = b.write();
    w.at(t, untyped("app:cursor+.0")).set(&Value::Int(1)).unwrap();
    assert_eq!(w.commit(), Err(Error::Permission { tid: t, needs: Role::Write }));
    assert_eq!(b.at(t, untyped("app:cursor+.0")).get().unwrap(), None);
    assert_eq!(durable_marks(&b), before);
    // a's own chain under t: admin through t
    let (x, y) = a
        .commit_with(|w| {
            let x = w.create_held_with_admin(t)?;
            let y = w.create_held_with_admin(x)?;
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
    let (db, c) = setup(0);
    let typing = db.aspect_key("win:typing+.0").unwrap();
    let note = ak("app:note+.0");
    let t = db.commit_with(|w| w.create_held()).unwrap();
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
    w.at(t, untyped("app:x+.0")).set(&Value::Int(1)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(_))));
}

// spec/data-model.md §2 (signal), spec/sync-compaction.md §2: each fire of an ephemeral signal reaches the
// aspect's history listener once, as it was fired, and nothing else: no page shows it (nobody holds
// it), reads and value watches stay absent; any other op is Invalid
#[test]
fn ephemeral_signal_fires_reach_history_listener_once_spec_data_model_2() {
    let (db, _c) = setup(0);
    let ring = db.aspect_key("win:ring+~0").unwrap();
    let mut w = db.write();
    let t = w.create_held().unwrap();
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
                assert_eq!((c.stamp.author, c.kind, p.valid), (db.author(), osis::CommitKind::Content, true));
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
    w.at(t, untyped("app:sig+~0")).path(osis::p!["k"]).set(&Value::Int(1)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(_))));
}

// spec/data-model.md §2, spec/commits.md §5 Signals: a signal without `+` reads absent and each
// write is a commit kept in history (the thing's setting keeps it), heard through `on_fire` alone
// (`on_change` sees nothing); a revert writes nothing back for it
#[test]
fn signal_without_ephemeral_is_history_spec_commits_5() {
    let (db, _c) = setup(0);
    db.register_schema("log.osis", "revision 1;\nsignal app:log~0: string;\n").unwrap();
    let log = db.aspect_key("app:log~0").unwrap();
    let t = db.commit_with(|w| { let t = w.create_held()?; keep_all(w, t); Ok(t) }).unwrap();
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
    let (db, _c) = setup(0);
    db.register_schema("k.osis", "revision 1;\nsignal app:log~0: string;\naspect app:n.0: string;\n").unwrap();
    let (log, n) = (db.aspect_key("app:log~0").unwrap(), db.aspect_key("app:n.0").unwrap());
    let t = db.commit_with(|w| { let t = w.create_held()?; keep_all(w, t); Ok(t) }).unwrap();
    let refused = |f: &dyn Fn(&mut osis::Write<'_>) -> osis::Result<()>, word: &str| {
        let mut w = db.write();
        f(&mut w).unwrap();
        assert!(matches!(w.commit(), Err(Error::Invalid(m)) if m.contains(word)), "{word}");
    };
    refused(&|w| w.at(t, log.clone()).set(&s("x")), "fire");
    refused(&|w| w.at(t, log.clone()).overwrite(&s("x")), "fire");
    refused(&|w| w.at(t, log.clone()).remove(), "fire");
    refused(&|w| w.at(t, n.clone()).fire(&s("x")), "set");
    refused(&|w| { w.at(t, log.clone()).fire(&s("x"))?; w.at(t, log.clone()).fire(&s("y")) }, "once");
    refused(&|w| w.at(t, untyped("app:raw+~0")).set(&s("x")), "fire");
    refused(&|w| w.at(t, untyped("app:raw+.0")).fire(&s("x")), "set");
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
