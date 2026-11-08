//! Undo, redo and revert write back only kept history (spec/crdt.md §4.6, spec/commits.md §7,
//! notes/listener-design.md): whether an undo works, and what it writes, follows from the
//! history setting and the edit's age alone, durable and ephemeral alike, never from what a node
//! happens to hold.

use osis::internals::CommitRaw as _;
use crate::common::TestWrites as _;
use osis::internals::Internals as _;
use crate::common::*;
use crate::common::CreateIn;
use osis::{CommitKind, CommitQuery, DynamicAspectKey, NotUndoableReason, Error, MemStore, Osis, Scope, Value};

/// Aspects keeping history a day, and ones keeping none, durable and ephemeral.
const SCHEMA: &str = "revision 1;
keep_history(1d) aspect app:k.0: int;
aspect app:n.0: int;
aspect app:l.0: list<int>;
aspect app:m.0: map<string, int>;
keep_history(1d) ephemeral aspect app:ke+.0: int;
ephemeral aspect app:ne+.0: int;
";

const DAY: u64 = 86_400_000;

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
    Error::NotUndoable { commit: c, reason: NotUndoableReason::ContentGone }
}

/// `t`'s `name` set to each of `vs` in turn, a commit each; the last commit.
fn sets(db: &Osis, t: osis::Tid, name: &str, vs: &[i64]) -> osis::CommitId {
    let k = key(db, name);
    let mut last = None;
    for v in vs {
        last = Some(commit_with(db, |w| w.at(t, k.clone()).set(&Value::Int(*v))).id);
    }
    last.unwrap()
}

// spec/crdt.md §4.6: a register set twice with no history kept: its undo would write back the
// replaced value, which no kept history holds: `NotUndoable{ContentGone}`, from `undo_target` as
// from `undo`, nothing written; the same after a reopen. A first set is no different: a write does
// not record what it overwrote.
#[test]
fn register_without_history_not_undoable_spec_crdt_4_6() {
    let c = clock();
    let store = MemStore::new();
    let db = osis::internals::create(cfg(1, store.clone(), &c)).unwrap();
    db.register_schema("undo.osis", SCHEMA).unwrap();
    let t = db.commit_with(|w| w.create()).unwrap();
    let first = sets(&db, t, "app:n.0", &[1]);
    let scope = Scope::Aspects(vec![(t, ak("app:n.0"))]);
    assert_eq!(db.undo(&scope), Err(gone(first)), "a first set");
    let second = sets(&db, t, "app:n.0", &[2]);
    let marks = db.engine(|e| e.commit_ids().len());
    assert_eq!(db.undo_target(&scope), Err(gone(second)));
    assert_eq!(db.undo(&scope), Err(gone(second)));
    assert_eq!(db.revert(second), Err(gone(second)));
    assert_eq!((db.engine(|e| e.commit_ids().len()), db.at(t, key(&db, "app:n.0")).get().unwrap()), (marks, int(2)), "nothing written");
    drop(db);
    let db = osis::internals::open(cfg(2, store, &c)).unwrap();
    assert_eq!(db.undo(&scope), Err(gone(second)), "after a reopen");
}

// spec/crdt.md §4.6: with history kept the replaced value comes back from it: after a reopen, and
// from a second node of the account that holds the commits; past the keep bound it is
// `NotUndoable` by age.
#[test]
fn register_with_history_undoes_anywhere_spec_crdt_4_6() {
    let c = clock();
    let store = MemStore::new();
    let db = osis::internals::create(cfg(1, store.clone(), &c)).unwrap();
    db.register_schema("undo.osis", SCHEMA).unwrap();
    let t = db.commit_with(|w| w.create()).unwrap();
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
    let t = a.commit_with(|w| w.create()).unwrap();
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

fn scope_of(t: osis::Tid) -> Scope {
    Scope::Aspects(vec![(t, ak("app:k.0"))])
}

// spec/crdt.md §4.6: one edit undoes to one outcome whether the body it replaced is still held or
// was compacted into a snapshot: with history kept the value comes back either way, with none
// the undo is `NotUndoable` either way.
#[test]
fn undo_alike_held_or_compacted_spec_crdt_4_6() {
    for name in ["app:k.0", "app:n.0"] {
        let outcome = |compact: bool| {
            let db = setup(3);
            let t = db.commit_with(|w| w.create()).unwrap();
            let first = sets(&db, t, name, &[1]);
            if compact {
                let k = ak(name);
                db.engine(|e| {
                    e.snapshot(&t, &k)?;
                    e.drop_body(&first.raw(), &t, &k)
                })
                .unwrap();
                assert!(!db.engine(|e| e.body_not_dropped(&first.raw(), &t, &k)), "compacted");
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

// spec/crdt.md §4.6: what only takes away what it made undoes with no history kept: a list insert,
// a map entry's first creation; redoing such an undo writes the taken value back, which needs
// history: `NotUndoable`. With history a first register set undoes to absent and redoes.
#[test]
fn takings_undo_without_history_redo_needs_it_spec_crdt_4_6() {
    let db = setup(4);
    let t = db.commit_with(|w| w.create()).unwrap();
    let (l, m) = (key(&db, "app:l.0"), key(&db, "app:m.0"));
    commit_with(&db, |w| w.at(t, l.clone()).set(&Value::List(vec![Value::Int(1)])));
    commit_with(&db, |w| w.at(t, l.clone()).path(osis::p![]).splice(1..1, &[Value::Int(2)]));
    let list = Scope::Aspects(vec![(t, ak("app:l.0"))]);
    let undo = db.undo(&list).unwrap().unwrap();
    assert_eq!(db.at(t, l.clone()).get().unwrap(), Some(Value::List(vec![Value::Int(1)])), "the insert undone");
    assert_eq!(db.redo(&list), Err(gone(undo.id)), "a redo writes the insert back");
    assert_eq!(db.redo_target(&list), Err(gone(undo.id)));
    commit_with(&db, |w| w.at(t, m.clone()).path(osis::p!["a"]).set(&Value::Int(1)));
    db.undo(&Scope::Aspects(vec![(t, ak("app:m.0"))])).unwrap().unwrap();
    assert_eq!(db.at(t, m).get().unwrap(), None, "the first entry undone");
    let k = key(&db, "app:k.0");
    sets(&db, t, "app:k.0", &[7]);
    let kept = Scope::Aspects(vec![(t, ak("app:k.0"))]);
    db.undo(&kept).unwrap().unwrap();
    assert_eq!(db.at(t, k.clone()).get().unwrap(), None);
    db.redo(&kept).unwrap().unwrap();
    assert_eq!(db.at(t, k).get().unwrap(), int(7));
}

// spec/crdt.md §4.6, notes/ephemeral.md Undo: ephemeral writes undo as durable ones do, from the
// history their aspect keeps in memory: a replace undoes and redoes with `keep_history`, is
// `NotUndoable` without; each write and revert is an ephemeral commit, listed like any, and
// nothing reaches the store.
#[test]
fn ephemeral_undo_from_kept_history_spec_crdt_4_6() {
    let db = setup(5);
    let t = db.commit_with(|w| w.create()).unwrap();
    let marks = || db.engine(|e| (e.commit_ids().len(), e.core.generation));
    let before = marks();
    sets(&db, t, "app:ke+.0", &[1, 2]);
    let plain = sets(&db, t, "app:ne+.0", &[1, 2]);
    let scope = Scope::Aspects(vec![(t, ak("app:ke+.0"))]);
    let get = || db.at(t, key(&db, "app:ke+.0")).get().unwrap();
    let all = db.commits(&CommitQuery { scope: Some(scope.clone()), ..Default::default() }).unwrap();
    assert_eq!(all.len(), 2, "two writes");
    assert!(all.iter().all(|e| e.kind == CommitKind::Content && e.in_effect && db.engine(|x| x.holds_memory(&e.commit.id.raw()))));
    let u = db.undo(&scope).unwrap().unwrap();
    assert_eq!(get(), int(1));
    let found = db.commits(&CommitQuery { scope: Some(scope.clone()), reverts: Some(all[0].commit.id), ..Default::default() }).unwrap();
    assert_eq!(found.iter().map(|e| (e.commit.id, e.kind)).collect::<Vec<_>>(), vec![(u.id, CommitKind::Revert)]);
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
    let x = other.commit_with(|w| w.create()).unwrap();
    let oid = sets(&other, x, "app:ke+.0", &[1]);
    assert!(matches!(db.revert(oid), Err(Error::Invalid(_))));
}

// notes/ephemeral.md API (Undo): Thing and Group scopes cover durable aspects; an ephemeral
// aspect (a cursor) is in scope only when named by `Scope::Aspects`, so document undo never
// steps through cursor moves.
#[test]
fn thing_scope_skips_cursor_spec_crdt_4_6() {
    let db = setup(7);
    let (text, cursor) = (key(&db, "app:k.0"), key(&db, "app:ke+.0"));
    let mut w = db.write();
    let d = w.create_with_content(db.me()).unwrap();
    w.commit().unwrap();
    db.commit_set(d, text.clone(), &Value::Int(1)).unwrap();
    db.commit_set(d, cursor.clone(), &Value::Int(1)).unwrap();
    db.commit_set(d, cursor.clone(), &Value::Int(2)).unwrap();
    let doc = Scope::Thing(d);
    assert!(db.commits(&CommitQuery { scope: Some(doc.clone()), ..Default::default() }).unwrap().iter().all(|e| !e.aspects.iter().any(|(_, a)| a.ephemeral())));
    db.undo(&doc).unwrap().unwrap();
    assert_eq!(db.at(d, text).get().unwrap(), None, "the text change, not a cursor move");
    assert_eq!(db.at(d, cursor.clone()).get().unwrap(), int(2));
    let cur = Scope::Aspects(vec![(d, ak("app:ke+.0"))]);
    db.undo(&cur).unwrap().unwrap();
    assert_eq!(db.at(d, cursor.clone()).get().unwrap(), int(1));
    db.redo(&cur).unwrap().unwrap();
    assert_eq!(db.at(d, cursor).get().unwrap(), int(2));
}

// notes/ephemeral.md API (Undo): an aspect scope over a durable and an ephemeral aspect: undo
// steps newest first across durable and ephemeral changes, redo back.
#[test]
fn mixed_scope_undo_order_spec_crdt_4_6() {
    let db = setup(8);
    let (body, draft) = (key(&db, "app:k.0"), key(&db, "app:ke+.0"));
    let (f, item) = db
        .commit_with(|w| {
            let f = w.create_with_content(db.me())?;
            let item = w.create_with_content(db.me())?;
            w.group(f).add(osis::Member::Item(item))?;
            Ok((f, item))
        })
        .unwrap();
    let e = db.commit_with(|w| w.create_in(db.me(), &[f])).unwrap();
    db.commit_set(item, body.clone(), &Value::Int(1)).unwrap();
    db.commit_set(e, draft.clone(), &Value::Int(1)).unwrap();
    db.commit_set(item, body.clone(), &Value::Int(2)).unwrap();
    db.commit_set(e, draft.clone(), &Value::Int(2)).unwrap();
    let scope = Scope::Aspects(vec![(item, ak("app:k.0")), (e, ak("app:ke+.0"))]);
    let state = || (db.at(item, body.clone()).get().unwrap(), db.at(e, draft.clone()).get().unwrap());
    db.undo(&scope).unwrap().unwrap();
    assert_eq!(state(), (int(2), int(1)));
    db.undo(&scope).unwrap().unwrap();
    assert_eq!(state(), (int(1), int(1)));
    db.undo(&scope).unwrap().unwrap();
    assert_eq!(state(), (int(1), None));
    db.redo(&scope).unwrap().unwrap();
    assert_eq!(state(), (int(1), int(1)));
    db.redo(&scope).unwrap().unwrap();
    assert_eq!(state(), (int(2), int(1)));
    db.redo(&scope).unwrap().unwrap();
    assert_eq!(state(), (int(2), int(2)));
}

// spec/crdt.md §4.6 Expiry: a commit's `expires` overrides its keys' defaults, and its undo has no use
// for them: what the undo writes expires as what it copies back, so a commit that could be made can be
// undone and redone. Durable and ephemeral alike.
#[test]
fn undo_takes_no_key_default_spec_crdt_4_6() {
    let db = setup(30);
    db.register_schema("rv.osis", "revision 1;\nexpires(30d) keep_history(1d) aspect app:d.0: int;\nkeep_history(1d) aspect app:p.0: int;\nexpires(30s) keep_history(1d) ephemeral aspect app:de+.0: int;\nkeep_history(1d) ephemeral aspect app:pe+.0: int;").unwrap();
    let t = db.commit_with(|w| w.create_with_content(db.me())).unwrap();
    for (x, y) in [("app:d.0", "app:p.0"), ("app:de+.0", "app:pe+.0")] {
        let (a, b) = (db.aspect_key(x).unwrap(), db.aspect_key(y).unwrap());
        let mut w = db.write();
        w.expires(osis::Expiry::In(std::time::Duration::from_secs(3600)));
        w.at(t, a.clone()).set(&Value::Int(1)).unwrap();
        w.at(t, b.clone()).set(&Value::Int(1)).unwrap();
        w.commit().unwrap();
        let scope = Scope::Aspects(vec![(t, ak(x)), (t, ak(y))]);
        db.undo(&scope).unwrap().unwrap();
        assert_eq!((db.at(t, a.clone()).get().unwrap(), db.at(t, b.clone()).get().unwrap()), (None, None));
        db.redo(&scope).unwrap().unwrap();
        assert_eq!((db.at(t, a).get().unwrap(), db.at(t, b).get().unwrap()), (int(1), int(1)));
    }
}

// spec/commits.md §6, §7, spec/crdt.md §4.6: an undo is one commit. One that would copy back a value
// expiring beside one that does not is refused, saying so, with nothing applied and nothing older
// undone; once the value has expired there is nothing to copy back, and it goes through.
#[test]
fn undo_needing_two_expiries_waits_spec_crdt_4_6() {
    let c = clock();
    let db = osis::internals::create(cfg(31, MemStore::new(), &c)).unwrap();
    db.register_schema("two.osis", "revision 1;\nkeep_history(1d) aspect app:a.0: int;\nkeep_history(1d) aspect app:b.0: int;\nkeep_history(1d) ephemeral aspect app:c+.0: int;\nkeep_history(1d) ephemeral aspect app:d+.0: int;").unwrap();
    let t = db.commit_with(|w| w.create_with_content(db.me())).unwrap();
    for (x, y) in [("app:a.0", "app:b.0"), ("app:c+.0", "app:d+.0")] {
        let (a, b) = (db.aspect_key(x).unwrap(), db.aspect_key(y).unwrap());
        db.commit_set(t, b.clone(), &Value::Int(0)).unwrap();
        let mut w = db.write();
        w.expires(osis::Expiry::In(std::time::Duration::from_secs(3600)));
        w.at(t, a.clone()).set(&Value::Int(0)).unwrap();
        w.commit().unwrap();
        let mut w = db.write();
        w.at(t, a.clone()).set(&Value::Int(2)).unwrap();
        w.at(t, b.clone()).set(&Value::Int(2)).unwrap();
        w.commit().unwrap();
        let scope = Scope::Aspects(vec![(t, ak(x)), (t, ak(y))]);
        let marks = db.engine(|e| e.commit_ids().len());
        assert!(matches!(db.undo(&scope), Err(Error::Invalid(m)) if m.contains("undo") && !m.contains("separate commits")));
        assert_eq!(db.engine(|e| e.commit_ids().len()), marks);
        assert_eq!((db.at(t, a.clone()).get().unwrap(), db.at(t, b.clone()).get().unwrap()), (int(2), int(2)));
        c.advance(3_700_000);
        db.engine(|e| e.tick().unwrap());
        db.undo(&scope).unwrap().unwrap();
        assert_eq!((db.at(t, a).get().unwrap(), db.at(t, b).get().unwrap()), (None, int(0)));
    }
}
