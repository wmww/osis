//! Local ephemeral things and aspects (notes/ephemeral.md, step 1): in memory, no commit, no
//! store write; persistence at the first durable write with the owner chain; restart forgets;
//! rights through the nearest durable owner; expiry in memory; signal aspects.

use crate::common::*;
use crate::common::CreateIn;
use crate::common::world::World;
use osis::{ChangeId, Config, Error, Lifetimes, MemStore, Osis, Role, Source, StoreAt, Value};
use std::sync::mpsc::channel;
use std::time::Duration;

const SCHEMA: &str = "schema 0x0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e;\nrevision 1;\n\
type win = struct { 0 title: string, 1 notes: list<string> };\n\
aspect /win/state: win [ephemeral];\n\
aspect /win/typing: bool [ephemeral, expires: 5s];\n\
aspect /win/cursor: map<tid, int> [presence];\n\
aspect /win/ring: string [signal];\n\
aspect /win/saved: string;\n";

fn setup(seed: u64) -> (Osis, std::sync::Arc<osis::ManualClock>) {
    let c = clock();
    let db = Osis::create(cfg(seed, MemStore::new(), &c)).unwrap().0;
    db.register_schema_source("win.osis", SCHEMA).unwrap();
    (db, c)
}

/// (held commits, engine generation): a store transaction that changes anything moves the
/// generation.
fn durable_marks(db: &Osis) -> (usize, u64) {
    db.engine(|e| (e.commit_ids().len(), e.core.generation))
}

fn field(id: u64) -> osis::Path {
    osis::Path(vec![osis::Step::Field(id)])
}

fn s(x: &str) -> Value {
    Value::Str(x.into())
}

// notes/ephemeral.md Model, Local engine: an ephemeral thing and its ephemeral aspects (typed,
// with path ops) are written, read and watched with no commit and no store write; an
// ephemeral aspect of a durable thing likewise. spec/data-model.md §1, §2
#[test]
fn write_and_watch_without_commit_spec_data_model_2() {
    let (db, _c) = setup(1);
    let state = db.key("/win/state").unwrap();
    let before = durable_marks(&db);
    let mut w = db.write();
    let win = w.create(db.me()).unwrap();
    w.at(win, state.clone()).set(&Value::Map([(Value::Int(0), s("draft")), (Value::Int(1), Value::List(vec![s("a")]))].into())).unwrap();
    let done = w.commit().unwrap().unwrap();
    assert!(matches!(done.id, ChangeId::Ephemeral(_)));
    assert_eq!(durable_marks(&db), before, "no commit, no store write");
    assert!(db.knows(win));
    assert_eq!(db.owner_of(win), Some(db.me()));
    let c = db.created(win).unwrap();
    assert_eq!((c.commit, c.ts, c.node, c.actor), (None, done.ts, db.node(), db.me()));
    assert_eq!(db.role_on(win), Some(Role::Admin));
    assert_eq!(db.at(win, state.clone()).path(field(0)).get::<String>().unwrap().as_deref(), Some("draft"));
    let (tx, rx) = channel();
    let _sub = db.at(win, state.clone()).on_change(move |_, c| tx.send(c).unwrap()).unwrap();
    assert_eq!(recv(&rx).source, Source::Initial);
    let watch = db.at(win, state.clone()).watch().unwrap();
    // a path op on the list inside the value
    let mut w = db.write();
    w.at(win, state.clone()).path(field(1)).insert(1, &[s("b")]).unwrap();
    let done = w.commit().unwrap().unwrap();
    let ch = recv(&rx);
    match ch.source {
        Source::Local(i) => assert_eq!((i.id, i.ts, i.node), (done.id, done.ts, db.node())),
        other => panic!("{other:?}"),
    }
    assert_eq!(db.at(win, state.clone()).path(field(1)).get::<Vec<String>>().unwrap(), Some(vec!["a".to_string(), "b".to_string()]));
    assert!(watch.changed_timeout(Duration::from_secs(20)));
    assert!(watch.current().unwrap().is_some());
    assert_eq!(db.aspects(win).unwrap(), vec![osis::Ak::new("/win/state").unwrap()]);
    // an ephemeral aspect of a durable thing
    let cur = ak("/app/selection").ephemeral();
    db.write_with(|w| w.at(db.home(), cur.clone()).set(&Value::Int(7))).unwrap();
    assert_eq!(db.get(db.home(), cur).unwrap(), Some(Value::Int(7)));
    assert_eq!(durable_marks(&db), before);
    assert!(db.aspects(db.home()).unwrap().contains(&ak("/app/selection")));
}

// notes/ephemeral.md Persistence: the first durable write on an ephemeral thing persists it
// and its ephemeral owner chain in one commit, keeping the tids; its ephemeral aspects stay
// ephemeral. spec/data-model.md §1, spec/commits.md §2
#[test]
fn first_durable_write_persists_chain_spec_commits_2() {
    let (db, _c) = setup(2);
    let state = db.key("/win/state").unwrap();
    let saved = db.key("/win/saved").unwrap();
    let (top, mid, leaf) = db
        .write_with(|w| {
            let top = w.create(db.me())?;
            let mid = w.create(top)?;
            let leaf = w.create(mid)?;
            w.at(leaf, ak("/app/draft").ephemeral()).set(&s("hello"))?;
            Ok((top, mid, leaf))
        })
        .unwrap();
    let other = db.write_with(|w| w.create(db.me())).unwrap();
    let before = db.engine(|e| e.commit_ids().len());
    db.write_with(|w| {
        w.at(leaf, saved.clone()).set(&s("hello"))?;
        w.at(leaf, state.clone()).set(&Value::Map([(Value::Int(0), s("t")), (Value::Int(1), Value::List(vec![]))].into()))
    })
    .unwrap();
    assert_eq!(db.engine(|e| e.commit_ids().len()), before + 1, "one commit");
    let c = db.created(leaf).unwrap().commit.expect("durable now");
    assert_eq!(db.created(mid).unwrap().commit, Some(c));
    assert_eq!(db.created(top).unwrap().commit, Some(c));
    assert_eq!(db.created(other).unwrap().commit, None, "untouched things stay ephemeral");
    let h = db.engine(|e| e.header(&c)).unwrap();
    let created: Vec<osis::Tid> = h.aspects.iter().filter(|a| a.ak.as_str() == "/created").map(|a| a.tid).collect();
    assert_eq!(created.len(), 3);
    assert!([top, mid, leaf].iter().all(|t| created.contains(t)));
    assert!(h.aspects.iter().all(|a| a.ak.as_str() != "/win/state" && a.ak.as_str() != "/app/draft"), "ephemeral aspects stay out of the commit");
    assert_eq!(db.get(leaf, saved).unwrap(), Some(s("hello")));
    assert_eq!(db.get(leaf, ak("/app/draft").ephemeral()).unwrap(), Some(s("hello")));
    assert!(db.get(leaf, state).unwrap().is_some());
    // placing an ephemeral thing keeps it ephemeral (notes/ephemeral.md Ephemeral placements)
    db.write_with(|w| w.place(other, db.home())).unwrap();
    assert_eq!(db.created(other).unwrap().commit, None);
    assert!(db.groups_of(other).contains(&db.home()));
}

// notes/ephemeral.md Local engine (Restart): on a `Dir` store, reopening forgets every
// ephemeral thing and ephemeral aspect; durable data is intact. spec/requirements.md (data
// model: ephemeral state in memory)
// spec/data-model.md §1
#[test]
fn restart_forgets_ephemeral_spec_requirements_ephemeral() {
    let dir = std::env::temp_dir().join(format!("osis-eph-{}-{:?}", std::process::id(), std::thread::current().id()).replace(['(', ')'], ""));
    let _ = std::fs::remove_dir_all(&dir);
    let c = clock();
    let at = |seed: u64| {
        let mut x = Config::at(StoreAt::Dir(dir.clone()));
        x.seed = Some(seed);
        x.clock = Some(c.clone());
        x
    };
    let db = Osis::create(at(1)).unwrap().0;
    let draft = ak("/app/draft").ephemeral();
    let (d, e) = db
        .write_with(|w| {
            let d = w.create(db.me())?;
            w.at(d, ak("/app/kept")).set(&Value::Int(1))?;
            w.at(d, draft.clone()).set(&Value::Int(2))?;
            let e = w.create(db.me())?;
            w.at(e, draft.clone()).set(&Value::Int(3))?;
            Ok((d, e))
        })
        .unwrap();
    assert_eq!(db.get(e, draft.clone()).unwrap(), Some(Value::Int(3)));
    db.close().unwrap();
    let db = Osis::open(at(2)).unwrap();
    assert!(!db.knows(e));
    assert_eq!(db.get(e, draft.clone()).unwrap(), None);
    assert_eq!(db.get(d, ak("/app/kept")).unwrap(), Some(Value::Int(1)));
    assert_eq!(db.get(d, draft).unwrap(), None);
    db.close().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

// notes/ephemeral.md Rights: an ephemeral thing's role is the role on a new thing owned by the
// nearest durable thing of its chain; a node with no write there can neither create one nor
// write ephemeral data on another's thing. spec/permissions.md §1
#[test]
fn rights_through_nearest_durable_owner_spec_permissions_1() {
    let (a, _c) = setup(3);
    let (b, _c2) = setup(4);
    let t = a.write_with(|w| {
        let t = w.create(a.me())?;
        w.at(t, ak("/app/kept")).set(&Value::Int(1))?;
        Ok(t)
    })
    .unwrap();
    deliver(&a, &b);
    assert_eq!(b.role_on(t), None);
    let before = durable_marks(&b);
    // an ephemeral thing under another actor's thing
    let mut w = b.write();
    w.create(t).unwrap();
    assert!(matches!(w.commit(), Err(Error::Permission { .. })));
    // ephemeral data on another actor's durable thing
    let mut w = b.write();
    w.at(t, ak("/app/cursor").ephemeral()).set(&Value::Int(1)).unwrap();
    assert_eq!(w.commit(), Err(Error::Permission { tid: t, needs: Role::Write }));
    assert_eq!(b.get(t, ak("/app/cursor").ephemeral()).unwrap(), None);
    assert_eq!(durable_marks(&b), before);
    // a's own ephemeral chain under t: admin through t
    let (x, y) = a
        .write_with(|w| {
            let x = w.create(t)?;
            let y = w.create(x)?;
            Ok((x, y))
        })
        .unwrap();
    assert_eq!(a.role_on(y), a.role_on(t));
    assert_eq!(a.role_on(x), Some(Role::Admin));
    assert!(!b.knows(y));
}

// notes/ephemeral.md Expiry: an expiring ephemeral write (explicit, or the key's default) goes
// at T in memory, without a commit; watches see `Derived(Expiry)`. spec/crdt.md §4.7
#[test]
fn ephemeral_expiry_spec_crdt_4_7() {
    let (db, c) = setup(5);
    let typing = db.key("/win/typing").unwrap();
    let note = ak("/app/note").ephemeral();
    let t = db
        .write_with(|w| {
            let t = w.create(db.me())?;
            w.at(t, typing.clone()).set(&Value::Bool(true))?;
            w.at(t, note.clone()).expires_in(Duration::from_secs(60)).set(&s("bye"))?;
            Ok(t)
        })
        .unwrap();
    let before = durable_marks(&db);
    let (tx, rx) = channel();
    let _sub = db.at(t, typing.clone()).on_change(move |_, c| tx.send(c).unwrap()).unwrap();
    recv(&rx);
    assert_eq!(db.engine(|e| e.next_ephemeral_timer()), Some(T0 + 5_000));
    c.advance(4_000);
    db.engine(|e| e.tick_ephemeral());
    assert_eq!(db.get(t, typing.clone()).unwrap(), Some(Value::Bool(true)));
    c.advance(2_000);
    db.engine(|e| e.tick_ephemeral());
    let ch = recv(&rx);
    assert_eq!((ch.source, ch.value), (Source::Derived(osis::Cause::Expiry), Ok(None)));
    assert_eq!(db.get(t, note.clone()).unwrap(), Some(s("bye")));
    // a later write of the same aspect is not touched by the old class
    db.write_with(|w| w.at(t, typing.clone()).expires_in(Duration::from_secs(30)).set(&Value::Bool(true))).unwrap();
    assert_eq!(db.get(t, typing).unwrap(), Some(Value::Bool(true)));
    c.advance(60_000);
    db.engine(|e| e.tick_ephemeral());
    assert_eq!(db.get(t, note).unwrap(), None);
    assert_eq!(durable_marks(&db), before);
    let mut w = db.write();
    assert!(matches!(w.at(t, ak("/app/x").ephemeral()).expires_in(Duration::ZERO).set(&Value::Int(1)), Err(Error::Invalid(_))));
}

// notes/ephemeral.md Model (signal aspects): each set reaches every callback once, never in
// state (reads and watches stay absent); any other op is Invalid. spec/data-model.md §2
#[test]
fn signal_aspects_fire_once_never_in_state_spec_data_model_2() {
    let (db, _c) = setup(6);
    let ring = db.key("/win/ring").unwrap();
    let t = db.write_with(|w| w.create(db.me())).unwrap();
    let (tx, rx) = channel();
    let _sub = db.at(t, ring.clone()).on_change(move |_, c| tx.send(c).unwrap()).unwrap();
    assert_eq!(recv(&rx).value, Ok(None));
    let (ttx, trx) = channel();
    let _th = db.watch_thing(t, move |_, c| ttx.send(c).unwrap());
    let watch = db.at(t, ring.clone()).watch().unwrap();
    let before = durable_marks(&db);
    for _ in 0..2 {
        db.write_with(|w| w.at(t, ring.clone()).set(&s("ding"))).unwrap();
    }
    for _ in 0..2 {
        let c = recv(&rx);
        assert_eq!(c.value, Ok(Some(s("ding"))));
        assert!(matches!(c.source, Source::Local(_)));
        assert_eq!(recv(&trx).value, Ok(Some(s("ding"))));
    }
    db.settle();
    assert!(rx.try_recv().is_err(), "once each");
    assert_eq!(db.get(t, ring.clone()).unwrap(), None);
    assert_eq!(watch.current().unwrap(), None);
    assert!(db.aspects(t).unwrap().is_empty());
    assert_eq!(durable_marks(&db), before);
    let mut w = db.write();
    w.at(t, ring.clone()).remove().unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(_))));
    let mut w = db.write();
    w.at(t, ak("/app/sig").signal()).path(osis::p!["k"]).set(&Value::Int(1)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(_))));
}

// notes/ephemeral.md API delta (Writes): a mixed batch is validated as a whole; when its
// durable half fails nothing applies, ephemeral half and new things included. A mixed batch
// that succeeds is one change with one `ts`.
// spec/data-model.md §2
#[test]
fn mixed_batch_all_or_nothing_spec_api_writes() {
    let (a, _c) = setup(7);
    let (b, _c2) = setup(8);
    let t = a.write_with(|w| {
        let t = w.create(a.me())?;
        w.at(t, ak("/app/kept")).set(&Value::Int(1))?;
        Ok(t)
    })
    .unwrap();
    deliver(&a, &b);
    let draft = ak("/app/draft").ephemeral();
    let mut w = b.write();
    let e = w.create(b.me()).unwrap();
    w.at(b.home(), draft.clone()).set(&Value::Int(1)).unwrap();
    w.at(t, ak("/app/kept")).set(&Value::Int(2)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Permission { .. })));
    assert!(!b.knows(e));
    assert_eq!(b.get(b.home(), draft.clone()).unwrap(), None);
    // an ephemeral op that fails fails the durable half too
    let before = durable_marks(&b);
    let mut w = b.write();
    w.at(b.home(), ak("/app/kept")).set(&Value::Int(3)).unwrap();
    w.at(b.home(), draft.clone()).retention(osis::Retention::default()).set(&Value::Int(1)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(_))));
    assert_eq!(durable_marks(&b), before);
    // success: one change
    let (tx, rx) = channel();
    let _sub = b.at(b.home(), draft.clone()).on_change(move |_, c| tx.send(c).unwrap()).unwrap();
    recv(&rx);
    let mut w = b.write();
    w.at(b.home(), ak("/app/kept")).set(&Value::Int(3)).unwrap();
    w.at(b.home(), draft.clone()).set(&Value::Int(4)).unwrap();
    let done = w.commit().unwrap().unwrap();
    let c = done.id.commit().expect("a commit");
    assert_eq!(b.engine(|e| e.header(&c)).unwrap().ts, done.ts);
    match recv(&rx).source {
        Source::Local(i) => assert_eq!((i.id, i.ts), (done.id, done.ts)),
        other => panic!("{other:?}"),
    }
}

// notes/ephemeral.md Deletion: deleting an ephemeral thing in no labeled closure frees it with
// the ephemeral things it owns; the tids read unknown.
// spec/data-model.md §1
#[test]
fn delete_frees_ephemeral_things() {
    let (db, _c) = setup(9);
    let draft = ak("/app/draft").ephemeral();
    let (x, y) = db
        .write_with(|w| {
            let x = w.create(db.me())?;
            let y = w.create(x)?;
            w.at(x, draft.clone()).set(&Value::Int(1))?;
            w.at(y, draft.clone()).set(&Value::Int(2))?;
            w.place(y, db.home())?;
            Ok((x, y))
        })
        .unwrap();
    let (tx, rx) = channel();
    let _sub = db.at(x, draft.clone()).on_change(move |_, c| tx.send(c).unwrap()).unwrap();
    recv(&rx);
    db.write_with(|w| w.delete(x)).unwrap();
    assert_eq!(recv(&rx).value, Ok(None));
    assert!(!db.knows(x) && !db.knows(y));
    assert_eq!(db.get(y, draft).unwrap(), None);
    assert!(!group_of(&db, db.home()).items.contains(&y), "an owned thing's placement goes with it");
    let mut w = db.write();
    assert_eq!(w.create(x), Err(Error::UnknownThing { tid: x }));
}

fn bench_n() -> i64 {
    std::env::var("OSIS_BENCH_N").ok().and_then(|v| v.parse().ok()).unwrap_or(100_000)
}

// notes/ephemeral.md Local engine (cost): `OSIS_BENCH_N` local ephemeral sets of one aspect,
// each its own batch, against `bench_btreemap_sets`; compare with tools/icount on a release
// build (notes/testing.md), subtracting a run with `OSIS_BENCH_N=0`. spec: none (cost)
#[test]
#[ignore = "bench: release, by hand"]
fn bench_ephemeral_sets() {
    let n = bench_n();
    let db = db(1);
    // `OSIS_BENCH_DURABLE=1`: the same through durable commits, for comparison
    let life = if std::env::var_os("OSIS_BENCH_DURABLE").is_some() { osis::Lifetime::Durable } else { osis::Lifetime::Ephemeral };
    let k = osis::Untyped::new(ak("/app/x"), life);
    let t = db.write_with(|w| w.create_durable(db.me())).unwrap();
    for i in 0..n {
        db.write_with(|w| w.at(t, k.clone()).set(&Value::Int(i))).unwrap();
    }
    assert_eq!(db.get(t, k).unwrap(), (n > 0).then(|| Value::Int(n - 1)));
}

// The baseline of `bench_ephemeral_sets`: the same sets into an in-memory map. spec: none (cost)
#[test]
#[ignore = "bench: release, by hand"]
fn bench_btreemap_sets() {
    let n = bench_n();
    let t = db(1).me();
    let mut m = std::collections::BTreeMap::new();
    for i in 0..n {
        m.insert((t, "/app/x".to_string()), Value::Int(i));
    }
    assert_eq!(std::hint::black_box(m).len(), usize::from(n > 0));
}



/// Alice's synced group `g` with Bob granted `role` on it, through one server.
fn shared(role: Role) -> (World, Osis, Osis, osis::Tid) {
    let mut w = World::new();
    let sv = w.add_server();
    let (alice, _) = w.person(1, &[sv]);
    let (bob, _) = w.person(2, &[sv]);
    w.run();
    let card = bob.contact_card().unwrap();
    w.run();
    let b = w.until(alice.import_contact(&card), 1000, 10).unwrap();
    let mut wr = alice.write();
    let g = wr.create(alice.me()).unwrap();
    wr.place(g, alice.home()).unwrap();
    wr.make_group(g).unwrap();
    wr.commit().unwrap();
    alice.sync(g, &[]).unwrap();
    alice.grant(g, b, role, Default::default()).unwrap();
    w.run();
    (w, alice, bob, g)
}

// notes/ephemeral.md Rights: readers cannot write ephemeral data (spec/requirements.md: readers
// only read): a reader of the nearest durable owner can neither create an ephemeral thing under
// it, write an ephemeral aspect on it nor fire a signal there; a writer can.
// spec/permissions.md §1
#[test]
fn reader_cannot_write_ephemeral_spec_permissions_1() {
    let (_w, _alice, bob, g) = shared(Role::Read);
    assert_eq!(bob.role_on(g), Some(Role::Read));
    let before = durable_marks(&bob);
    let mut w = bob.write();
    w.create(g).unwrap();
    assert!(matches!(w.commit(), Err(Error::Permission { .. })), "a reader creates under g");
    let mut w = bob.write();
    w.at(g, ak("/app/cursor").ephemeral()).set(&Value::Int(1)).unwrap();
    assert_eq!(w.commit(), Err(Error::Permission { tid: g, needs: Role::Write }));
    let mut w = bob.write();
    w.at(g, ak("/app/sig").signal()).set(&Value::Int(1)).unwrap();
    assert_eq!(w.commit(), Err(Error::Permission { tid: g, needs: Role::Write }));
    assert_eq!(durable_marks(&bob), before);
    let (_w, _alice, bob, g) = shared(Role::Write);
    let e = bob
        .write_with(|w| {
            let e = w.create(g)?;
            w.at(e, ak("/app/d").ephemeral()).set(&Value::Int(1))?;
            w.at(g, ak("/app/cursor").ephemeral()).set(&Value::Int(1))?;
            Ok(e)
        })
        .unwrap();
    assert_eq!(bob.role_on(e), Some(Role::Write));
}

// notes/ephemeral.md Persistence: a membership operation or a move on an ephemeral thing first
// persists it (and a move's ephemeral new owner) by its own commit; a durable reference to an
// ephemeral tid persists nothing (it may dangle). spec/data-model.md §1
#[test]
fn membership_and_move_persist_first_spec_data_model_1() {
    let (_w, alice, bob, g) = shared(Role::Read);
    let e = alice.write_with(|w| w.create(g)).unwrap();
    alice.grant(e, bob.me(), Role::Write, Default::default()).unwrap();
    assert!(alice.created(e).unwrap().commit.is_some(), "persisted first");
    assert!(alice.roster(e).contains_key(&bob.me()));
    let (db, _c) = setup(20);
    let (d, e) = db
        .write_with(|w| {
            let e = w.create(db.me())?;
            let d = w.create_durable(db.me())?;
            w.at(d, ak("/app/ref")).set(&Value::Tid(e))?;
            Ok((d, e))
        })
        .unwrap();
    assert_eq!(db.created(e).unwrap().commit, None, "a reference persists nothing");
    let o = db.write_with(|w| w.create(db.me())).unwrap();
    let copy = db.move_thing(d, o, &[]).unwrap();
    assert!(db.created(o).unwrap().commit.is_some());
    assert_eq!(db.owner_of(copy), Some(o));
    let copy = db.move_thing(e, o, &[]).unwrap();
    assert!(db.created(copy).unwrap().commit.is_some());
}

// notes/ephemeral.md API delta (Writes): an ephemeral op that fails when it resolves (a list
// index past the end) fails the whole batch: no commit, no new thing. Persisting a thing leaves
// the ephemeral things it owns ephemeral; `/group` takes ephemeral writes only through group
// ops (an ephemeral-keyed raw write is Invalid).
// spec/data-model.md §1, §2
#[test]
fn mixed_batch_resolution_failure_and_partial_chain() {
    let (db, _c) = setup(21);
    let state = db.key("/win/state").unwrap();
    let before = durable_marks(&db);
    let mut w = db.write();
    let e = w.create(db.me()).unwrap();
    w.at(db.home(), ak("/app/kept")).set(&Value::Int(3)).unwrap();
    w.at(e, state.clone()).path(field(1)).insert(5, &[s("x")]).unwrap();
    assert!(w.commit().is_err());
    assert!(!db.knows(e));
    assert_eq!(durable_marks(&db), before);
    assert_eq!(db.get(db.home(), ak("/app/kept")).unwrap(), None);
    let draft = ak("/app/d").ephemeral();
    let (p, c) = db
        .write_with(|w| {
            let p = w.create(db.me())?;
            let c = w.create(p)?;
            w.at(c, draft.clone()).set(&Value::Int(1))?;
            w.at(p, ak("/app/kept")).set(&Value::Int(1))?;
            Ok((p, c))
        })
        .unwrap();
    assert!(db.created(p).unwrap().commit.is_some());
    assert_eq!(db.created(c).unwrap().commit, None);
    let n = db.engine(|e| e.commit_ids().len());
    db.write_with(|w| w.at(c, ak("/app/kept")).set(&Value::Int(2))).unwrap();
    assert_eq!(db.engine(|e| e.commit_ids().len()), n + 1);
    assert!(db.created(c).unwrap().commit.is_some());
    assert_eq!(db.get(c, draft).unwrap(), Some(Value::Int(1)));
    let mut w = db.write();
    w.at(p, ak("/group").ephemeral()).set(&Value::Int(1)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(_))));
}

fn group_of(db: &Osis, g: osis::Tid) -> osis::core::Group {
    db.get(g, osis::core::GROUP).unwrap().unwrap_or_default()
}

/// The durable side of `g`'s `/group` (what the store holds; reads join the ephemeral side).
fn durable_items(db: &Osis, g: osis::Tid) -> Vec<osis::Tid> {
    db.engine(|e| {
        let v = e.state(&g, &ak("/group")).unwrap().and_then(|f| f.read());
        v.map(|v| osis::schema::AspectKey::decode(&osis::core::GROUP, &v).unwrap().items.into_iter().collect()).unwrap_or_default()
    })
}

// notes/ephemeral.md Ephemeral placements: an ephemeral item placed in a durable group is an
// ephemeral write of the group's `/group`: it lists in the group, in its `/groups` and in a
// watch of the group, with no commit and no store write; unplacing it is ephemeral too.
// spec/data-model.md §8
#[test]
fn ephemeral_placement_lists_without_commit_spec_data_model_8() {
    let (db, _c) = setup(30);
    let home = db.home();
    let (tx, rx) = channel();
    let _sub = db.at(home, osis::core::GROUP).on_change(move |_, c| tx.send(c).unwrap()).unwrap();
    recv(&rx);
    let before = durable_marks(&db);
    let mut w = db.write();
    let t = w.create(db.me()).unwrap();
    w.place(t, home).unwrap();
    let done = w.commit().unwrap().unwrap();
    assert!(matches!(done.id, ChangeId::Ephemeral(_)));
    assert_eq!(durable_marks(&db), before, "no commit, no store write");
    assert!(group_of(&db, home).items.contains(&t));
    assert!(!durable_items(&db, home).contains(&t));
    assert!(db.groups_of(t).contains(&home));
    assert_eq!(db.get(t, osis::core::GROUPS).unwrap().map(|g| g.contains(&home)), Some(true));
    let ch = recv(&rx);
    assert!(matches!(ch.source, Source::Local(_)));
    assert!(ch.value.unwrap().unwrap().items.contains(&t));
    db.write_with(|w| w.unplace(t, home)).unwrap();
    assert_eq!(durable_marks(&db), before);
    assert!(!group_of(&db, home).items.contains(&t));
    assert!(db.groups_of(t).is_empty());
}

// notes/ephemeral.md Persistence, Ephemeral placements: persisting a placed ephemeral thing
// writes its `/created` and the durable `/group` add (with the placement's expiry) in one
// commit, and the ephemeral element goes. spec/data-model.md §8, spec/commits.md §2, §6
#[test]
fn persisting_makes_placements_durable_spec_data_model_8() {
    let (db, _c) = setup(31);
    let home = db.home();
    let saved = db.key("/win/saved").unwrap();
    let (t, g) = db
        .write_with(|w| {
            let g = w.create_durable(db.me())?;
            w.make_group(g)?;
            Ok((w.create(db.me())?, g))
        })
        .unwrap();
    db.write_with(|w| w.place(t, home)).unwrap();
    db.write_with(|w| w.place_expiring(t, g, Some(Duration::from_secs(3600)))).unwrap();
    let n = db.engine(|e| e.commit_ids().len());
    db.write_with(|w| w.at(t, saved.clone()).set(&s("x"))).unwrap();
    assert_eq!(db.engine(|e| e.commit_ids().len()), n + 1, "one commit");
    let c = db.created(t).unwrap().commit.expect("persisted");
    let h = db.engine(|e| e.header(&c)).unwrap();
    let entry = |tid: osis::Tid, a: &str| h.aspects.iter().find(|x| x.tid == tid && x.ak.as_str() == a).cloned();
    assert!(entry(t, "/created").is_some());
    assert_eq!(entry(home, "/group").expect("home add").expires, None);
    assert_eq!(entry(g, "/group").expect("g add").expires, Some(T0 + 3_600_000));
    assert!(durable_items(&db, home).contains(&t) && durable_items(&db, g).contains(&t));
    // the ephemeral side no longer names it: removing the durable element removes it
    db.write_with(|w| w.unplace(t, home)).unwrap();
    assert!(!group_of(&db, home).items.contains(&t));
    assert!(db.groups_of(t).contains(&g) && !db.groups_of(t).contains(&home));
    // an unplace in the persisting batch wins over converting that placement
    let u = db
        .write_with(|w| {
            let u = w.create(db.me())?;
            w.place(u, home)?;
            Ok(u)
        })
        .unwrap();
    db.write_with(|w| {
        w.at(u, saved.clone()).set(&s("y"))?;
        w.unplace(u, home)
    })
    .unwrap();
    assert!(db.created(u).unwrap().commit.is_some());
    assert!(!group_of(&db, home).items.contains(&u) && !durable_items(&db, home).contains(&u));
}

// notes/ephemeral.md Ephemeral placements: a draft placed in a folder lands there at save
// (the save copies the draft's ephemeral content into a durable aspect).
// spec/data-model.md §1, §8
#[test]
fn draft_lands_in_folder_at_save_spec_data_model_8() {
    let (db, _c) = setup(32);
    let state = db.key("/win/state").unwrap();
    let saved = db.key("/win/saved").unwrap();
    let folder = db
        .write_with(|w| {
            let f = w.create_durable(db.me())?;
            w.make_group(f)?;
            w.place(f, db.home())?;
            Ok(f)
        })
        .unwrap();
    let draft = db
        .write_with(|w| {
            let d = w.create(db.me())?;
            w.place(d, folder)?;
            w.at(d, state.clone()).set(&Value::Map([(Value::Int(0), s("title")), (Value::Int(1), Value::List(vec![s("body")]))].into()))?;
            Ok(d)
        })
        .unwrap();
    assert_eq!(db.groups_of(draft), vec![folder]);
    assert!(durable_items(&db, folder).is_empty());
    db.write_with(|w| w.at(draft, saved.clone()).set(&s("title\nbody"))).unwrap();
    assert!(db.created(draft).unwrap().commit.is_some());
    assert_eq!(durable_items(&db, folder), vec![draft]);
    assert_eq!(group_of(&db, folder).items.into_iter().collect::<Vec<_>>(), vec![draft]);
}

// notes/ephemeral.md Local engine (Restart), Ephemeral placements: a restart before persisting
// leaves no ghost: no durable group names the ephemeral tid, and it reads unknown.
// spec/data-model.md §8
#[test]
fn restart_leaves_no_dead_tids_in_groups_spec_data_model_8() {
    let dir = std::env::temp_dir().join(format!("osis-eph-place-{}-{:?}", std::process::id(), std::thread::current().id()).replace(['(', ')'], ""));
    let _ = std::fs::remove_dir_all(&dir);
    let c = clock();
    let at = |seed: u64| {
        let mut x = Config::at(StoreAt::Dir(dir.clone()));
        x.seed = Some(seed);
        x.clock = Some(c.clone());
        x
    };
    let db = Osis::create(at(1)).unwrap().0;
    let home = db.home();
    let (g, e, sub) = db
        .write_with(|w| {
            let g = w.create_durable(db.me())?;
            w.make_group(g)?;
            let e = w.create(db.me())?;
            w.place(e, home)?;
            w.place(e, g)?;
            // an ephemeral subgroup of a durable group
            let sub = w.create(db.me())?;
            w.make_group(sub)?;
            w.add_subgroup(g, sub)?;
            Ok((g, e, sub))
        })
        .unwrap();
    assert!(group_of(&db, g).items.contains(&e) && group_of(&db, g).subgroups.contains(&sub));
    db.close().unwrap();
    let db = Osis::open(at(2)).unwrap();
    assert!(!db.knows(e) && !db.knows(sub));
    for x in [home, g] {
        let gr = group_of(&db, x);
        assert!(!gr.items.contains(&e) && !gr.subgroups.contains(&sub), "{x}");
        assert!(!durable_items(&db, x).contains(&e));
    }
    assert!(db.groups_of(e).is_empty());
    db.close().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

// notes/ephemeral.md Ephemeral placements: a durable item placed in an ephemeral group persists
// the group (and the group's own ephemeral placements, and that it is a group); an ephemeral
// group of ephemeral items stays in memory, its unplace persists nothing.
// spec/data-model.md §1, §8
#[test]
fn durable_item_persists_ephemeral_group_spec_data_model_8() {
    let (db, _c) = setup(33);
    let home = db.home();
    let before = durable_marks(&db);
    let (g, a, b) = db
        .write_with(|w| {
            let g = w.create(db.me())?;
            w.make_group(g)?;
            w.place(g, home)?;
            w.add_subgroup(home, g)?;
            let a = w.create(db.me())?;
            let b = w.create(db.me())?;
            w.place(a, g)?;
            w.place(b, g)?;
            Ok((g, a, b))
        })
        .unwrap();
    assert_eq!(durable_marks(&db), before, "all ephemeral");
    assert!(db.groups_of(a).contains(&g) && db.groups_of(a).contains(&home));
    db.write_with(|w| w.unplace(b, g)).unwrap();
    assert_eq!(durable_marks(&db), before, "unplace on an ephemeral group persists nothing");
    assert_eq!(db.created(g).unwrap().commit, None);
    let d = db.write_with(|w| w.create_durable(db.me())).unwrap();
    db.write_with(|w| w.place(d, g)).unwrap();
    assert!(db.created(g).unwrap().commit.is_some(), "the group persisted");
    assert_eq!(durable_items(&db, g), vec![d]);
    assert!(durable_items(&db, home).contains(&g), "its placement too");
    assert!(group_of(&db, home).subgroups.contains(&g) && db.engine(|x| x.durable_groups_of(&d)).contains(&home), "and its subgroup entry");
    assert_eq!(db.created(a).unwrap().commit, None, "its ephemeral items stay ephemeral");
    assert!(group_of(&db, g).items.contains(&a));
    // a group persisted with no durable item keeps its (empty) durable `/group`
    let e = db
        .write_with(|w| {
            let e = w.create(db.me())?;
            w.make_group(e)?;
            Ok(e)
        })
        .unwrap();
    db.write_with(|w| w.at(e, ak("/app/kept")).set(&Value::Int(1))).unwrap();
    assert!(db.engine(|x| x.has_durable(&e, &ak("/group"))));
}

// notes/ephemeral.md Ephemeral placements: a node that may write a persisting thing but no
// longer the group it placed it in ephemerally keeps that placement ephemeral and reports
// `PlacementNotPersisted` naming item and group. spec/permissions.md §1
#[test]
fn placement_not_persisted_without_write_on_group_spec_permissions_1() {
    let (mut w, alice, bob, g) = shared(Role::Write);
    let t = bob
        .write_with(|x| {
            let t = x.create(bob.me())?;
            x.place(t, g)?;
            Ok(t)
        })
        .unwrap();
    assert!(group_of(&bob, g).items.contains(&t));
    w.until(alice.demote(g, bob.me(), osis::Lower::To(Role::Read), osis::Demotion { sync: osis::WaitForSync::Skip, backdate: None }), 1000, 10).unwrap();
    w.run();
    assert_eq!(bob.role_on(g), Some(Role::Read));
    let (tx, rx) = channel();
    let _sub = bob.on_diagnostic(move |_, d| {
        if d.kind == osis::DiagnosticKind::PlacementNotPersisted {
            let _ = tx.send(d.tids);
        }
    });
    bob.write_with(|x| x.at(t, ak("/app/kept")).set(&Value::Int(1))).unwrap();
    assert!(bob.created(t).unwrap().commit.is_some());
    assert_eq!(recv(&rx), vec![t, g]);
    assert!(group_of(&bob, g).items.contains(&t), "still placed, ephemerally");
    assert!(!durable_items(&bob, g).contains(&t));
}

// notes/ephemeral.md Ephemeral placements: persisting an item placed with an expiry in an
// ephemeral group persists the group in the same commit whatever the tid order (its empty
// `/group` takes the placement's expiry, which removes no value of it), and it stays a group
// after the placement expires. spec/crdt.md §4.7, spec/data-model.md §8
#[test]
fn expiring_placement_persists_ephemeral_group_spec_data_model_8() {
    for order in 0..4 {
        let (db, c) = setup(40 + order);
        let (g, x) = db
            .write_with(|w| {
                let a = w.create(db.me())?;
                let b = w.create(db.me())?;
                let (g, x) = if (a < b) == (order % 2 == 0) { (a, b) } else { (b, a) };
                w.make_group(g)?;
                Ok((g, x))
            })
            .unwrap();
        db.write_with(|w| w.place_expiring(x, g, Some(Duration::from_secs(60)))).unwrap();
        db.write_with(|w| w.at(x, ak("/app/kept")).set(&Value::Int(1))).unwrap();
        assert!(db.created(g).unwrap().commit.is_some(), "order {order}");
        assert_eq!(durable_items(&db, g), vec![x]);
        c.advance(120_000);
        db.engine(|e| {
            e.tick().unwrap();
            e.tick_ephemeral();
        });
        assert_eq!(db.get(g, osis::core::GROUP).unwrap(), Some(Default::default()), "order {order}: still a group");
    }
}

// notes/ephemeral.md Persistence: the persistence fixpoint through cycles (a group holding
// itself, two groups holding each other, an item owned by and placed in an ephemeral group of
// that pair) persists every thing involved with its placements, and a reopened store reads
// the same groups. spec/data-model.md §1, §8
#[test]
fn persistence_through_group_cycles_spec_data_model_8() {
    let dir = std::env::temp_dir().join(format!("osis-eph-cycles-{}-{:?}", std::process::id(), std::thread::current().id()).replace(['(', ')'], ""));
    let _ = std::fs::remove_dir_all(&dir);
    let c = clock();
    let at = |seed: u64| {
        let mut x = Config::at(StoreAt::Dir(dir.clone()));
        x.seed = Some(seed);
        x.clock = Some(c.clone());
        x
    };
    let db = Osis::create(at(1)).unwrap().0;
    let home = db.home();
    let (g, g1, g2, x) = db
        .write_with(|w| {
            let g = w.create(db.me())?;
            w.make_group(g)?;
            w.add_subgroup(g, g)?;
            w.place(g, g)?;
            let g1 = w.create(db.me())?;
            let g2 = w.create(g1)?;
            w.make_group(g1)?;
            w.make_group(g2)?;
            w.add_subgroup(g1, g2)?;
            w.add_subgroup(g2, g1)?;
            w.add_subgroup(home, g1)?;
            let x = w.create(g2)?;
            w.place(x, g2)?;
            Ok((g, g1, g2, x))
        })
        .unwrap();
    assert!(db.groups_of(g).contains(&g));
    assert!(db.groups_of(x).contains(&g1) && db.groups_of(x).contains(&home));
    db.write_with(|w| w.at(g, ak("/app/kept")).set(&Value::Int(1))).unwrap();
    db.write_with(|w| w.at(x, ak("/app/kept")).set(&Value::Int(2))).unwrap();
    for t in [g, g1, g2, x] {
        assert!(db.created(t).unwrap().commit.is_some(), "{t} persisted");
    }
    let check = |db: &Osis| {
        assert!(durable_items(db, g).contains(&g) && durable_items(db, g2).contains(&x));
        assert!(db.engine(|e| e.durable_groups_of(&x)).is_superset(&[g1, g2, home].into()));
        assert!(group_of(db, g1).subgroups.contains(&g2) && group_of(db, g2).subgroups.contains(&g1));
    };
    check(&db);
    db.close().unwrap();
    let db = Osis::open(at(2)).unwrap();
    check(&db);
    db.close().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

// notes/ephemeral.md Persistence: a placement that does not convert (unplaced by the
// persisting batch) does not persist its ephemeral group. spec/data-model.md §8
#[test]
fn unplaced_placement_does_not_persist_its_group_spec_data_model_8() {
    let (db, _c) = setup(45);
    let (g, x) = db
        .write_with(|w| {
            let g = w.create(db.me())?;
            w.make_group(g)?;
            let x = w.create(db.me())?;
            w.place(x, g)?;
            Ok((g, x))
        })
        .unwrap();
    db.write_with(|w| {
        w.at(x, ak("/app/kept")).set(&Value::Int(1))?;
        w.unplace(x, g)
    })
    .unwrap();
    assert!(db.created(x).unwrap().commit.is_some());
    assert_eq!(db.created(g).unwrap().commit, None);
    assert!(!group_of(&db, g).items.contains(&x));
}
