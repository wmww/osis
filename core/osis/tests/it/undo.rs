//! Undo, redo and revert touch only kept history (spec/crdt.md §4.6, spec/commits.md §7,
//! notes/listener-design.md): whether an undo works, and what it writes, follows from the
//! history setting and the edit's age alone, durable and ephemeral alike, never from what a node
//! happens to hold.

use osis::internals::Held as _;
use osis::internals::CommitRaw as _;
use crate::common::TestWrites as _;
use osis::internals::Internals as _;
use crate::common::*;
use osis::{CommitKind, CommitQuery, DynamicAspectKey, NotUndoableReason, Error, MemStore, Osis, Scope, Value};

/// The aspects: `kept_thing` keeps `KEPT` a day, the others none, durable and ephemeral.
const SCHEMA: &str = "revision 1;
aspect app:k.0: int;
aspect app:n.0: int;
aspect app:l.0: list<int>;
aspect app:m.0: map<string, int>;
aspect app:km.0: map<string, int>;
ephemeral aspect app:ke+.0: int;
ephemeral aspect app:ne+.0: int;
";

const DAY: u64 = 86_400_000;

/// The aspects a `kept_thing`'s setting keeps a day.
const KEPT: [&str; 3] = ["app:k.0", "app:km.0", "app:ke+.0"];

/// In `w`, `t`'s setting keeping `KEPT` a day.
fn keeps(w: &mut osis::Write<'_>, t: osis::Tid) {
    let x = setting(&KEPT.map(|a| (a, crate::common::DAY)));
    w.at(t, osis::core::RETENTION).set(&x).unwrap();
}

/// A thing whose setting keeps `KEPT` a day.
fn kept_thing(db: &Osis) -> osis::Tid {
    db.commit_with(|w| {
        let t = w.create_held()?;
        keeps(w, t);
        Ok(t)
    })
    .unwrap()
}

fn setup(seed: u64) -> Osis {
    let db = osis::internals::create(cfg(seed, MemStore::new(), &clock())).unwrap();
    db.register_schema("undo.osis", SCHEMA).unwrap();
    db
}

fn key(db: &Osis, name: &str) -> DynamicAspectKey {
    db.aspect_key(name).unwrap()
}

fn int(n: i64) -> Option<Value> {
    Some(Value::Int(n))
}

fn gone(c: osis::CommitId) -> Error {
    Error::NotUndoable { commit: c, reason: NotUndoableReason::NotKept }
}

/// `t`'s `name` set to each of `vs` in turn, a commit each; the last commit.
fn sets(db: &Osis, t: osis::Tid, name: &str, vs: &[i64]) -> osis::CommitId {
    let k = key(db, name);
    let mut last = None;
    for v in vs {
        last = Some(commit_with(db, |w| w.at(t, k.clone()).set(&Value::Int(*v))).stamp.id);
    }
    last.unwrap()
}

// spec/commits.md §7 (kept history only), Tess's decision: on an aspect no setting keeps, no
// write is undone, a first set and an insert (which take nothing back) included: refused at once,
// its body held, by `undo_target`, `undo` and `revert` alike, nothing written; the same from a
// second node of the account holding the commits, and after a reopen; ephemeral writes alike.
#[test]
fn no_history_no_undo_spec_commits_7() {
    let c = clock();
    let store = MemStore::new();
    let db = osis::internals::create(cfg(1, store.clone(), &c)).unwrap();
    db.register_schema("undo.osis", SCHEMA).unwrap();
    let t = kept_thing(&db);
    let first = sets(&db, t, "app:n.0", &[1]);
    let insert = commit_with(&db, |w| w.at(t, key(&db, "app:l.0")).path(osis::p![]).splice(0..0, &[Value::Int(2)])).stamp.id;
    for (x, a) in [(first, "app:n.0"), (insert, "app:l.0")] {
        assert!(db.engine(|e| e.body_not_dropped(&x.raw(), &t, &ak(a))), "{a}: held, not compacted");
        let scope = Scope::Aspects(vec![(t, ak(a))]);
        let marks = db.engine(|e| e.commit_ids().len());
        assert_eq!(db.undo_target(&scope), Err(gone(x)), "{a}");
        assert_eq!(db.undo(&scope), Err(gone(x)), "{a}");
        assert_eq!(db.revert(x), Err(gone(x)), "{a}");
        assert_eq!(db.engine(|e| e.commit_ids().len()), marks, "{a}: nothing written");
    }
    let eph = sets(&db, t, "app:ne+.0", &[1]);
    assert_eq!(db.undo(&Scope::Aspects(vec![(t, ak("app:ne+.0"))])), Err(gone(eph)), "an ephemeral first write alike");
    assert_eq!(db.at(t, key(&db, "app:n.0")).get().unwrap(), int(1));
    drop(db);
    let db = osis::internals::open(cfg(2, store, &c)).unwrap();
    assert_eq!(db.undo(&Scope::Aspects(vec![(t, ak("app:n.0"))])), Err(gone(first)), "after a reopen");
    // a second node
    let (a, b, _) = paired();
    for n in [&a, &b] {
        n.register_schema("undo.osis", SCHEMA).unwrap();
    }
    let t = kept_thing(&a);
    let x = sets(&a, t, "app:n.0", &[1]);
    deliver(&a, &b);
    assert_eq!(b.at(t, key(&b, "app:n.0")).get().unwrap(), int(1), "b holds it");
    let scope = Scope::Aspects(vec![(t, ak("app:n.0"))]);
    assert_eq!(b.undo_target(&scope), Err(gone(x)), "from a second node");
    assert_eq!(b.revert(x), Err(gone(x)));
}

// spec/crdt.md §4.6 (undo needs kept history): with history kept the replaced value comes back
// from it: after a reopen, and from a second node of the account that holds the commits; past the
// keep bound of the value it replaced (the undone set itself kept while live) it is `NotUndoable`
// by age.
#[test]
fn register_with_history_undoes_anywhere_spec_crdt_4_6() {
    let c = clock();
    let store = MemStore::new();
    let db = osis::internals::create(cfg(1, store.clone(), &c)).unwrap();
    db.register_schema("undo.osis", SCHEMA).unwrap();
    let t = kept_thing(&db);
    sets(&db, t, "app:k.0", &[1, 2, 3]);
    drop(db);
    let db = osis::internals::open(cfg(2, store, &c)).unwrap();
    db.register_schema("undo.osis", SCHEMA).unwrap();
    let scope = Scope::Aspects(vec![(t, ak("app:k.0"))]);
    db.undo(&scope).unwrap().unwrap();
    assert_eq!(db.at(t, key(&db, "app:k.0")).get().unwrap(), int(2), "after a reopen");
    // a second node
    let (a, b, c) = paired();
    for n in [&a, &b] {
        n.register_schema("undo.osis", SCHEMA).unwrap();
    }
    let t = kept_thing(&a);
    sets(&a, t, "app:k.0", &[1, 2]);
    deliver(&a, &b);
    b.undo(&scope_of(t)).unwrap().unwrap();
    assert_eq!(b.at(t, key(&b, "app:k.0")).get().unwrap(), int(1), "from a second node");
    deliver(&b, &a);
    assert_eq!(a.at(t, key(&a, "app:k.0")).get().unwrap(), int(1));
    // past the bound
    let last = sets(&a, t, "app:k.0", &[5]);
    c.advance(DAY + 1);
    assert_eq!(a.undo(&scope_of(t)), Err(gone(last)), "older than its keep bound");
}

// spec/commits.md §7: a redo writes the undone write back, so it needs that write kept: on an
// aspect the thing's setting keeps, a map entry's creation undoes and redoes.
#[test]
fn redo_follows_undone_write_spec_commits_7() {
    let db = setup(0);
    let m = key(&db, "app:km.0");
    let t = kept_thing(&db);
    let scope = Scope::Aspects(vec![(t, ak("app:km.0"))]);
    commit_with(&db, |w| w.at(t, m.clone()).path(osis::p!["b"]).set(&Value::Int(2)));
    db.undo(&scope).unwrap().unwrap();
    db.redo(&scope).unwrap().unwrap();
    assert_eq!(db.at(t, m.clone()).path(osis::p!["b"]).get().unwrap(), int(2), "a kept creation");
}

fn scope_of(t: osis::Tid) -> Scope {
    Scope::Aspects(vec![(t, ak("app:k.0"))])
}

// spec/crdt.md §4.6: one edit undoes to one outcome whether or not the aspect was compacted into
// a snapshot before it: with history kept the value comes back either way (the replaced body is
// kept while live), with none the undo is `NotUndoable` either way.
#[test]
fn undo_alike_held_or_compacted_spec_crdt_4_6() {
    for name in ["app:k.0", "app:n.0"] {
        let outcome = |compact: bool| {
            let db = setup(0);
            let t = kept_thing(&db);
            let first = sets(&db, t, name, &[1]);
            // compacted as node-sync compacts: a snapshot, then what it covers past its keep
            // bound drops (none of a body kept while live) and its commit is forgotten
            // (spec/commits.md §5 Keep bounds, Forgetting)
            if compact {
                let k = ak(name);
                db.engine(|e| e.snapshot(&t, &k)).unwrap();
                db.settle();
                let held = db.engine(|e| e.commit_ids().contains(&first.raw()) && e.body_not_dropped(&first.raw(), &t, &k));
                assert_eq!(held, name == "app:k.0", "{name}: kept while live, else dropped");
            }
            let second = sets(&db, t, name, &[2]);
            let r = db.undo(&Scope::Aspects(vec![(t, ak(name))])).map(|_| db.at(t, key(&db, name)).get().unwrap());
            r.map_err(|e| (e == gone(second)).then_some(()).ok_or(e))
        };
        let held = outcome(false);
        assert_eq!(held, outcome(true), "{name}");
        assert_eq!(held, if name == "app:k.0" { Ok(int(1)) } else { Err(Ok(())) }, "{name}");
    }
}

// spec/commits.md §7 (kept history only), Tess's decision: what only takes away what it made
// (a list insert) undoes and redoes while the setting keeps it, and is refused once it leaves
// history by the setting's bound (the list is kept until a time `T`), whether its body is still
// held or dropped as covered since: the setting decides, never compaction. With history a first register set undoes to absent and
// redoes.
#[test]
fn takings_undo_while_kept_spec_commits_7() {
    let c = clock();
    let db = osis::internals::create(cfg(0, MemStore::new(), &c)).unwrap();
    db.register_schema("undo.osis", SCHEMA).unwrap();
    let until = osis::History::Keep { until: osis::Time(T0 + 60_000), after_replaced: std::time::Duration::ZERO };
    let x = setting(&[("app:l.0", until), ("app:k.0", crate::common::DAY)]);
    let t = db.commit_with(|w| {
        let t = w.create_held()?;
        w.at(t, osis::core::RETENTION).set(&x)?;
        Ok(t)
    })
    .unwrap();
    let l = key(&db, "app:l.0");
    let la = ak("app:l.0");
    let list = Scope::Aspects(vec![(t, la.clone())]);
    let get = || db.at(t, l.clone()).get().unwrap();
    let ints = |xs: &[i64]| Some(Value::List(xs.iter().map(|x| Value::Int(*x)).collect()));
    commit_with(&db, |w| w.at(t, l.clone()).set(&Value::List(vec![Value::Int(1)])));
    commit_with(&db, |w| w.at(t, l.clone()).path(osis::p![]).splice(1..1, &[Value::Int(2)]));
    db.undo(&list).unwrap().unwrap();
    assert_eq!(get(), ints(&[1]), "the insert undone");
    db.redo(&list).unwrap().unwrap();
    assert_eq!(get(), ints(&[1, 2]), "and redone");
    let late = commit_with(&db, |w| w.at(t, l.clone()).path(osis::p![]).splice(2..2, &[Value::Int(3)])).stamp.id;
    c.advance(61_000);
    // past T nothing of the list undoes: refused for `late`, or, once its body dropped as covered
    // and its commits forgotten, nothing left to undo (spec/commits.md §5 Forgetting Limit:
    // forgetting narrows undo, never widens it)
    let target = db.undo_target(&list);
    assert!(matches!(target, Ok(None)) || target == Err(gone(late)), "past T: {target:?}");
    assert!(db.revert(late).is_err());
    let _ = db.undo(&list);
    assert_eq!(get(), ints(&[1, 2, 3]));
    let k = key(&db, "app:k.0");
    sets(&db, t, "app:k.0", &[7]);
    let kept = Scope::Aspects(vec![(t, ak("app:k.0"))]);
    db.undo(&kept).unwrap().unwrap();
    assert_eq!(db.at(t, k.clone()).get().unwrap(), None);
    db.redo(&kept).unwrap().unwrap();
    assert_eq!(db.at(t, k).get().unwrap(), int(7));
}

// spec/crdt.md §4.6, notes/ephemeral.md Undo: ephemeral writes undo as durable ones do, from the
// history the thing's setting keeps for their aspect in memory: a replace undoes and redoes where it keeps it, is
// `NotUndoable` without; each write and revert is an ephemeral commit, listed like any, and
// nothing reaches the store.
#[test]
fn ephemeral_undo_from_kept_history_spec_crdt_4_6() {
    let db = setup(5);
    let t = kept_thing(&db);
    let marks = || db.engine(|e| (e.commit_ids().len(), e.core.generation));
    let before = marks();
    sets(&db, t, "app:ke+.0", &[1, 2]);
    let plain = sets(&db, t, "app:ne+.0", &[1, 2]);
    let scope = Scope::Aspects(vec![(t, ak("app:ke+.0"))]);
    let get = || db.at(t, key(&db, "app:ke+.0")).get().unwrap();
    let all = db.writes(&scope, &CommitQuery::default()).unwrap().commits;
    assert_eq!(all.len(), 2, "two writes");
    assert!(all.iter().all(|e| e.kind == CommitKind::Content && e.in_effect && db.engine(|x| x.holds_memory(&e.stamp.id.raw()))));
    let u = db.undo(&scope).unwrap().unwrap();
    assert_eq!(get(), int(1));
    let found = db.writes(&scope, &CommitQuery { reverts: Some(all[0].stamp.id), ..Default::default() }).unwrap().commits;
    assert_eq!(found.iter().map(|e| (e.stamp.id, e.kind)).collect::<Vec<_>>(), vec![(u.stamp.id, CommitKind::Revert)]);
    db.undo(&scope).unwrap().unwrap();
    assert_eq!(get(), None, "absent before the first write");
    assert_eq!(db.undo(&scope).unwrap(), None);
    db.redo(&scope).unwrap().unwrap();
    db.redo(&scope).unwrap().unwrap();
    assert_eq!(get(), int(2));
    // a new change clears redo
    db.undo(&scope).unwrap().unwrap();
    sets(&db, t, "app:ke+.0", &[5]);
    assert_eq!(db.redo(&scope).unwrap(), None);
    assert_eq!(db.undo(&Scope::Aspects(vec![(t, ak("app:ne+.0"))])), Err(gone(plain)), "no history kept");
    assert_eq!(marks(), before, "no durable commit, no store write");
    // another node's commit is not known here
    let other = setup(6);
    let x = kept_thing(&other);
    let oid = sets(&other, x, "app:ke+.0", &[1]);
    assert!(matches!(db.revert(oid), Err(Error::Invalid(_))));
}

// spec/commits.md §7: a memory commit forgotten here (an expiring write superseded by its
// author's next one vanishes, spec/sync-compaction.md §2) still counts as a part the undone write may have
// replaced: two expiring sets keeping no history, then a setting keeping the aspect (the second
// set now kept while live): undoing it is `NotUndoable`, never the field emptied.
#[test]
fn undo_over_forgotten_ephemeral_part_not_undoable_spec_commits_7() {
    let db = osis::internals::create(cfg(0, MemStore::new(), &clock())).unwrap();
    db.register_schema("x.osis", "revision 1;\nexpires(1h) ephemeral aspect app:xe+.0: int;").unwrap();
    let t = kept_thing(&db);
    let first = sets(&db, t, "app:xe+.0", &[1]);
    let last = sets(&db, t, "app:xe+.0", &[2]);
    assert!(!db.engine(|e| e.holds_memory(&first.raw())), "the first set forgotten");
    keep_day(&db, t, &["app:xe+.0"]);
    let scope = Scope::Aspects(vec![(t, ak("app:xe+.0"))]);
    assert_eq!(db.undo_target(&scope), Err(gone(last)));
    assert_eq!(db.undo(&scope), Err(gone(last)));
    assert_eq!(db.at(t, key(&db, "app:xe+.0")).get().unwrap(), int(2), "nothing written");
}
