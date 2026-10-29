//! Local ephemeral things and aspects (notes/ephemeral.md, step 1): in memory, no commit, no
//! store write; persistence at the first durable write with the owner chain; restart forgets;
//! rights through the nearest durable owner; expiry in memory; signal aspects.

use crate::common::*;
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
    // placing an ephemeral thing persists it (until ephemeral placements)
    db.write_with(|w| w.place(other, db.home())).unwrap();
    assert!(db.created(other).unwrap().commit.is_some());
    assert!(db.groups_of(other).contains(&db.home()));
}

// notes/ephemeral.md Local engine (Restart): on a `Dir` store, reopening forgets every
// ephemeral thing and ephemeral aspect; durable data is intact. spec/requirements.md (data
// model: ephemeral state in memory)
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
// the ephemeral things it owns ephemeral; `/group` takes no ephemeral writes until ephemeral
// placements.
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
