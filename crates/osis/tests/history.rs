//! Undo, redo, history (notes/api.md Undo; spec/commits.md §7).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;
use common::*;
use osis::{DropReason, EntryState, Error, HistoryQuery, Place, UndoScope, Value};

// spec/commits.md §7, notes/api.md Undo: undo and redo walk this actor's own changes in
// scope; redo is an undo of the undo; a new undo after a redo undoes the redone change. A
// register edited twice undoes twice (spec/crdt.md §4.6: the second undo steps back through
// the first undo's restoring write), then redoes twice.
#[test]
fn undo_redo_cycle_spec_commits_7() {
    let db = db(1);
    let k = ak("/t/x");
    let mut w = db.write();
    let t = w.create(db.me(), Place::Unsynced).unwrap();
    w.commit().unwrap();
    db.write_with(|w| w.at(t, k.clone()).set(&Value::Int(1))).unwrap();
    db.write_with(|w| w.at(t, k.clone()).set(&Value::Int(2))).unwrap();
    let scope = UndoScope::Aspects(vec![(t, k.clone())]);
    let get = || db.get(t, k.clone()).unwrap();
    db.undo(&scope).unwrap().unwrap();
    assert_eq!(get(), Some(Value::Int(1)));
    db.redo(&scope).unwrap().unwrap();
    assert_eq!(get(), Some(Value::Int(2)));
    db.undo(&scope).unwrap().unwrap();
    assert_eq!(get(), Some(Value::Int(1)));
    db.undo(&scope).unwrap().unwrap();
    assert_eq!(get(), None);
    assert_eq!(db.undo(&scope).unwrap(), None);
    db.redo(&scope).unwrap().unwrap();
    assert_eq!(get(), Some(Value::Int(1)));
    db.redo(&scope).unwrap().unwrap();
    assert_eq!(get(), Some(Value::Int(2)));
    assert_eq!(db.redo(&scope).unwrap(), None);
    // and back again through the redone changes
    db.undo(&scope).unwrap().unwrap();
    assert_eq!(get(), Some(Value::Int(1)));
    db.undo(&scope).unwrap().unwrap();
    assert_eq!(get(), None);
    db.redo(&scope).unwrap().unwrap();
    assert_eq!(get(), Some(Value::Int(1)));
    // separate aspects undo step by step
    let scope = UndoScope::Thing(t);
    let (a, b) = (ak("/t/a"), ak("/t/b"));
    db.write_with(|w| w.at(t, a.clone()).set(&Value::Int(1))).unwrap();
    db.write_with(|w| w.at(t, b.clone()).set(&Value::Int(1))).unwrap();
    db.undo(&scope).unwrap().unwrap();
    db.undo(&scope).unwrap().unwrap();
    assert_eq!((db.get(t, a.clone()).unwrap(), db.get(t, b.clone()).unwrap()), (None, None));
    // another scope sees nothing to undo
    let other = UndoScope::Aspects(vec![(t, ak("/t/other"))]);
    assert_eq!(db.undo(&other).unwrap(), None);
}

// notes/api.md Undo (decided): a new change clears the redo stack.
#[test]
fn new_change_clears_redo_spec_commits_7() {
    let db = db(1);
    let (a, b) = (ak("/t/a"), ak("/t/b"));
    let mut w = db.write();
    let t = w.create(db.me(), Place::Unsynced).unwrap();
    w.commit().unwrap();
    db.write_with(|w| w.at(t, a.clone()).set(&Value::Int(1))).unwrap();
    let scope = UndoScope::Thing(t);
    db.undo(&scope).unwrap().unwrap();
    db.write_with(|w| w.at(t, b.clone()).set(&Value::Int(1))).unwrap();
    assert_eq!(db.redo(&scope).unwrap(), None);
    assert_eq!(db.get(t, a).unwrap(), None);
    // undo then redo still pairs up after the new change
    db.undo(&scope).unwrap().unwrap();
    assert_eq!(db.get(t, b.clone()).unwrap(), None);
    db.redo(&scope).unwrap().unwrap();
    assert_eq!(db.get(t, b).unwrap(), Some(Value::Int(1)));
}

// spec/commits.md §7: when the newest change's body was dropped, undo reports it and never
// undoes an older change instead.
#[test]
fn undo_blocked_by_dropped_body_spec_commits_7() {
    let db = db(1);
    let (a, b) = (ak("/t/a"), ak("/t/b"));
    let mut w = db.write();
    let t = w.create(db.me(), Place::Unsynced).unwrap();
    w.commit().unwrap();
    db.write_with(|w| w.at(t, a.clone()).set(&Value::Int(1))).unwrap();
    let newest = commit_with(&db, |w| w.at(t, b.clone()).set(&Value::Int(1))).commit;
    db.engine(|e| e.drop_body(&newest, &t, &b)).unwrap();
    assert_eq!(db.undo(&UndoScope::Thing(t)), Err(Error::NotUndoable { commit: newest, reason: DropReason::Compacted }));
    assert_eq!(db.get(t, a).unwrap(), Some(Value::Int(1)));
    assert_eq!(db.undo_commit(newest), Err(Error::NotUndoable { commit: newest, reason: DropReason::Compacted }));
}

// notes/node.md: an undo mutation carries nothing else.
#[test]
fn undo_mutation_alone_spec_commits_7() {
    let db = db(1);
    let mut w = db.write();
    let t = w.create(db.me(), Place::Unsynced).unwrap();
    let c = w.commit().unwrap().unwrap().commit;
    let mut m = osis::node::Mutation::new();
    m.undo(c).set(t, &ak("/t/x"), &Value::Int(1)).unwrap();
    assert!(matches!(db.engine(|e| e.commit(m)), Err(osis::node::Error::Misuse(_))));
}

// notes/api.md Undo: history lists everyone's changes in scope with their state; a change
// whose body was dropped is Dropped(Compacted), never a silent no-op; undo_commit undoes any
// entry this node may write.
#[test]
fn history_states_spec_crdt_4_6() {
    let db = db(1);
    let (k, j) = (ak("/t/x"), ak("/t/y"));
    let mut w = db.write();
    let g = w.create(db.me(), Place::Unsynced).unwrap();
    w.make_group(g).unwrap();
    let t = w.create(db.me(), Place::In(g)).unwrap();
    w.commit().unwrap();
    let c1 = commit_with(&db, |w| w.at(t, k.clone()).set(&Value::Int(1)));
    let mut w = db.write();
    w.act_as(db.node());
    w.at(t, j.clone()).set(&Value::Int(5)).unwrap();
    let c2 = w.commit().unwrap().unwrap();
    // the node's commit is not on me's stack, but undo_commit reverts it
    let u = db.undo_commit(c2.commit).unwrap();
    assert_eq!(db.get(t, j.clone()).unwrap(), None);
    let h = db.history(&UndoScope::Group(g), HistoryQuery::default()).unwrap();
    let state = |c: osis::CommitId| h.iter().find(|e| e.commit == c).map(|e| e.state);
    assert_eq!(state(c2.commit), Some(EntryState::Undone));
    assert_eq!(state(u.commit), Some(EntryState::Undoable));
    assert_eq!(state(c1.commit), Some(EntryState::Undoable));
    assert_eq!(h.iter().find(|e| e.commit == u.commit).unwrap().undoes, Some(c2.commit));
    assert_eq!(h.first().map(|e| e.commit), Some(u.commit));
    let paged = db.history(&UndoScope::Group(g), HistoryQuery { limit: 1, before: Some(u.ts) }).unwrap();
    assert_eq!(paged.len(), 1);
    assert_ne!(paged[0].commit, u.commit);
    // purge drops c1's body
    db.write_with(|w| w.at(t, k.clone()).purge()).unwrap();
    let h = db.history(&UndoScope::Aspects(vec![(t, k.clone())]), HistoryQuery::default()).unwrap();
    assert_eq!(h.iter().find(|e| e.commit == c1.commit).map(|e| e.state), Some(EntryState::Dropped(DropReason::Compacted)));
    assert!(db.undo_commit(osis::CommitId([7; 32])).is_err());
}

// spec/crdt.md §4.6: undo never steps back over a live later change: x = 1, 2, 1, 5; undoing
// the 5 restores 1, and a selective undo of the first write is then superseded (the later
// writes are still in effect), so x stays 1.
#[test]
fn undo_chain_stops_at_a_live_change_spec_crdt_4_6() {
    let db = db(1);
    let k = ak("/t/x");
    let mut w = db.write();
    let t = w.create(db.me(), Place::Unsynced).unwrap();
    w.commit().unwrap();
    let c1 = commit_with(&db, |w| w.at(t, k.clone()).set(&Value::Int(1)));
    commit_with(&db, |w| w.at(t, k.clone()).set(&Value::Int(2)));
    commit_with(&db, |w| w.at(t, k.clone()).set(&Value::Int(1)));
    commit_with(&db, |w| w.at(t, k.clone()).set(&Value::Int(5)));
    db.undo(&UndoScope::Thing(t)).unwrap().unwrap();
    assert_eq!(db.get(t, k.clone()).unwrap(), Some(Value::Int(1)));
    assert_eq!(db.undo_commit(c1.commit), Err(Error::NotUndoable { commit: c1.commit, reason: DropReason::Superseded }));
    assert_eq!(db.get(t, k).unwrap(), Some(Value::Int(1)));
}
