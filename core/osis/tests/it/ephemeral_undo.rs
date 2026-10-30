//! Undo, redo, revert and the commit query over ephemeral changes (notes/ephemeral.md API
//! delta, Local engine Undo; spec/crdt.md §4.6): an in-memory log of this session's own
//! ephemeral batches, the scope rule, mixed batches as one change, the history cap.

use osis::internals::Internals as _;
use crate::common::*;
use crate::common::CreateIn;
use osis::{ChangeId, CommitKind, CommitQuery, DropReason, Error, Lifetimes, MemStore, Osis, Scope, Value};

fn setup(seed: u64) -> Osis {
    Osis::create(cfg(seed, MemStore::new(), &clock())).unwrap().0
}

fn int(n: i64) -> Option<Value> {
    Some(Value::Int(n))
}

// notes/ephemeral.md API delta (Undo): own ephemeral batches are changes (`Ephemeral` kind):
// undo and redo step through them on an ephemeral thing like through commits, including a
// register written twice and "absent before"; nothing reaches the store. spec/crdt.md §4.6
#[test]
fn undo_redo_ephemeral_thing_spec_crdt_4_6() {
    let db = setup(1);
    let k = ak("/app/draft").ephemeral();
    let t = db.write_with(|w| w.create(db.me())).unwrap();
    let marks = || db.engine(|e| (e.commit_ids().len(), e.core.generation));
    let before = marks();
    db.write_with(|w| w.at(t, k.clone()).set(&Value::Int(1))).unwrap();
    db.write_with(|w| w.at(t, k.clone()).set(&Value::Int(2))).unwrap();
    let scope = Scope::Thing(t);
    let get = || db.get(t, k.clone()).unwrap();
    let all = db.commits(&CommitQuery::new().scope(scope.clone())).unwrap();
    assert_eq!(all.len(), 3, "the creation and two writes");
    assert!(all.iter().all(|e| e.kind == CommitKind::Ephemeral && e.in_effect && matches!(e.commit.id, ChangeId::Ephemeral(_))));
    let u = db.undo(&scope).unwrap().unwrap();
    assert!(matches!(u.id, ChangeId::Ephemeral(_)));
    assert_eq!(get(), int(1));
    let found = db.commits(&CommitQuery::new().scope(scope.clone()).reverts(all[0].commit.id)).unwrap();
    assert_eq!(found.iter().map(|e| (e.commit.id, e.kind)).collect::<Vec<_>>(), vec![(u.id, CommitKind::Ephemeral)]);
    let target = db.commits(&CommitQuery::new().scope(scope.clone()).reverted_by(u.id)).unwrap();
    assert_eq!((target[0].commit.id, target[0].in_effect), (all[0].commit.id, false));
    db.undo(&scope).unwrap().unwrap();
    assert_eq!(get(), None, "absent before the first write");
    assert!(db.knows(t));
    db.undo(&scope).unwrap().unwrap();
    assert!(!db.knows(t), "undoing the creation deletes");
    assert_eq!(db.undo(&scope).unwrap(), None);
    db.redo(&scope).unwrap().unwrap();
    assert!(db.knows(t) && get().is_none());
    db.redo(&scope).unwrap().unwrap();
    assert_eq!(get(), int(1));
    db.redo(&scope).unwrap().unwrap();
    assert_eq!(get(), int(2));
    assert_eq!(db.redo(&scope).unwrap(), None);
    db.undo(&scope).unwrap().unwrap();
    assert_eq!(get(), int(1));
    // a new change clears redo
    db.write_with(|w| w.at(t, k.clone()).set(&Value::Int(5))).unwrap();
    assert_eq!(db.redo(&scope).unwrap(), None);
    db.undo(&scope).unwrap().unwrap();
    assert_eq!(get(), int(1));
    assert_eq!(marks(), before, "no commit, no store write");
    // revert by id; an id this session never logged is Invalid
    let newest = db.commits(&CommitQuery::new().scope(scope.clone()).in_effect(true).kind(CommitKind::Ephemeral)).unwrap()[0].commit.id;
    db.revert(newest).unwrap();
    let other = setup(2);
    other
        .write_with(|w| {
            let x = w.create(other.me())?;
            w.at(x, k.clone()).set(&Value::Int(1))
        })
        .unwrap();
    let oid = other.commits(&CommitQuery::new().kind(CommitKind::Ephemeral)).unwrap()[0].commit.id;
    assert!(matches!(db.revert(oid), Err(Error::Invalid(_))));
}

// notes/ephemeral.md API delta (Undo): Thing and Group scopes cover durable aspects and
// ephemeral things; an ephemeral aspect of a durable thing (a cursor) is in scope only when
// named by `Scope::Aspects`, so document undo never steps through cursor moves.
#[test]
fn thing_scope_skips_cursor_spec_crdt_4_6() {
    let db = setup(3);
    let text = ak("/doc/text");
    let cursor = ak("/doc/cursor").ephemeral();
    let d = db.write_with(|w| w.create_durable(db.me())).unwrap();
    db.write_with(|w| w.at(d, text.clone()).set(&Value::Str("a".into()))).unwrap();
    db.write_with(|w| w.at(d, cursor.clone()).set(&Value::Int(1))).unwrap();
    db.write_with(|w| w.at(d, cursor.clone()).set(&Value::Int(2))).unwrap();
    let doc = Scope::Thing(d);
    assert!(db.commits(&CommitQuery::new().scope(doc.clone())).unwrap().iter().all(|e| e.kind != CommitKind::Ephemeral));
    db.undo(&doc).unwrap().unwrap();
    assert_eq!(db.get(d, text.clone()).unwrap(), None, "the text change, not a cursor move");
    assert_eq!(db.get(d, cursor.clone()).unwrap(), int(2));
    let cur = Scope::Aspects(vec![(d, ak("/doc/cursor"))]);
    db.undo(&cur).unwrap().unwrap();
    assert_eq!(db.get(d, cursor.clone()).unwrap(), int(1));
    db.redo(&cur).unwrap().unwrap();
    assert_eq!(db.get(d, cursor).unwrap(), int(2));
}

// notes/ephemeral.md API delta (Writes, Undo): a batch with a durable and an ephemeral half is
// one change (its commit); undo reverts both halves in one step, redo restores both.
#[test]
fn mixed_batch_undone_in_one_step_spec_crdt_4_6() {
    let db = setup(4);
    let x = ak("/t/x");
    let sel = ak("/t/sel").ephemeral();
    let d = db.write_with(|w| w.create_durable(db.me())).unwrap();
    let mut w = db.write();
    w.at(d, x.clone()).set(&Value::Int(1)).unwrap();
    w.at(d, sel.clone()).set(&Value::Int(7)).unwrap();
    let c = w.commit().unwrap().unwrap();
    assert!(matches!(c.id, ChangeId::Commit(_)));
    let scope = Scope::Aspects(vec![(d, x.clone()), (d, ak("/t/sel"))]);
    let found = db.commits(&CommitQuery::new().scope(scope.clone())).unwrap();
    assert_eq!(found[0].commit.id, c.id);
    assert_eq!(found[0].aspects.len(), 2, "both halves in one entry: {:?}", found[0].aspects);
    let u = db.undo(&scope).unwrap().unwrap();
    assert!(matches!(u.id, ChangeId::Commit(_)), "the revert has a durable half");
    assert_eq!((db.get(d, x.clone()).unwrap(), db.get(d, sel.clone()).unwrap()), (None, None));
    db.redo(&scope).unwrap().unwrap();
    assert_eq!((db.get(d, x.clone()).unwrap(), db.get(d, sel.clone()).unwrap()), (int(1), int(7)));
    // the Thing scope covers the batch through its durable half: undo reverts it whole
    db.undo(&Scope::Thing(d)).unwrap().unwrap();
    assert_eq!((db.get(d, x).unwrap(), db.get(d, sel).unwrap()), (None, None));
}

// notes/ephemeral.md API delta (Undo): a folder scope covers its durable item and its
// ephemeral draft; undo steps newest first across durable and ephemeral changes, redo back.
#[test]
fn mixed_scope_undo_order_spec_crdt_4_6() {
    let db = setup(5);
    let (body, draft) = (ak("/t/body"), ak("/t/draft").ephemeral());
    let (f, item, e) = db
        .write_with(|w| {
            let f = w.create_durable(db.me())?;
            w.make_group(f)?;
            let item = w.create_durable(db.me())?;
            w.place(item, f)?;
            let e = w.create(db.me())?;
            w.place(e, f)?;
            Ok((f, item, e))
        })
        .unwrap();
    db.write_with(|w| w.at(item, body.clone()).set(&Value::Int(1))).unwrap();
    db.write_with(|w| w.at(e, draft.clone()).set(&Value::Int(1))).unwrap();
    db.write_with(|w| w.at(item, body.clone()).set(&Value::Int(2))).unwrap();
    db.write_with(|w| w.at(e, draft.clone()).set(&Value::Int(2))).unwrap();
    let scope = Scope::Group(f);
    let state = || (db.get(item, body.clone()).unwrap(), db.get(e, draft.clone()).unwrap());
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
    // an ephemeral placement is a change of the folder: undone and redone like one
    db.write_with(|w| w.unplace(e, f)).unwrap();
    assert!(!db.groups_of(e).within.contains(&f));
    db.undo(&scope).unwrap().unwrap();
    assert!(db.groups_of(e).within.contains(&f));
    db.redo(&scope).unwrap().unwrap();
    assert!(!db.groups_of(e).within.contains(&f));
}

// notes/ephemeral.md Bounds (`ephemeral_history`): past the cap the oldest ephemeral batches
// leave the log; undo reaching one is `NotUndoable{Compacted}` (nothing older instead), and a
// revert of it too.
#[test]
fn not_undoable_past_history_cap_spec_crdt_4_6() {
    let c = clock();
    let mut x = cfg(6, MemStore::new(), &c);
    x.ephemeral_history = 8_000;
    let db = Osis::create(x).unwrap().0;
    let k = ak("/app/n").ephemeral();
    let t = db.write_with(|w| w.create(db.me())).unwrap();
    let mut ids = Vec::new();
    for i in 0..40 {
        ids.push(db.write().tap(|w| w.at(t, k.clone()).set(&Value::Int(i)).unwrap()).commit().unwrap().unwrap().id);
    }
    let scope = Scope::Thing(t);
    let logged = db.commits(&CommitQuery::new().scope(scope.clone())).unwrap().len();
    assert!(logged > 0 && logged < 40, "{logged}");
    let mut undone = 0;
    let err = loop {
        match db.undo(&scope) {
            Ok(Some(_)) => undone += 1,
            Ok(None) => panic!("ran out without reaching the dropped batches"),
            Err(e) => break e,
        }
        assert!(undone <= 40);
    };
    assert!(undone > 0);
    assert!(matches!(err, Error::NotUndoable { commit: ChangeId::Ephemeral(_), reason: DropReason::Compacted }), "{err:?}");
    assert_eq!(db.revert(ids[0]), Err(Error::NotUndoable { commit: ids[0], reason: DropReason::Compacted }));
    // at 0 no ephemeral change is undoable
    let mut x = cfg(7, MemStore::new(), &c);
    x.ephemeral_history = 0;
    let db = Osis::create(x).unwrap().0;
    let t = db.write_with(|w| w.create(db.me())).unwrap();
    db.write_with(|w| w.at(t, k.clone()).set(&Value::Int(1))).unwrap();
    assert!(matches!(db.undo(&Scope::Thing(t)), Err(Error::NotUndoable { reason: DropReason::Compacted, .. })));
}

trait Tap: Sized {
    fn tap(mut self, f: impl FnOnce(&mut Self)) -> Self {
        f(&mut self);
        self
    }
}
impl Tap for osis::Write<'_> {}

// notes/ephemeral.md Step 2 as built, spec/crdt.md §4.6 Undoing a creation: saving a placed
// draft is no creation (the draft existed), so undoing the save returns to the draft: its
// durable writes reverted, the placement's durable add included, its ephemeral placement and
// draft content back, the thing known (its record stays durable). A further undo reverts the
// draft's creation and deletes it; redo brings back the draft, then the save. A new save of a
// draft again converts its placement like the first.
#[test]
fn undo_of_save_restores_the_draft_spec_crdt_4_6() {
    let db = setup(9);
    let draft = ak("/app/draft").ephemeral();
    let body = ak("/app/body");
    let f = db.write_with(|w| { let f = w.create_durable(db.me())?; w.make_group(f)?; Ok(f) }).unwrap();
    let e = db
        .write_with(|w| {
            let e = w.create(db.me())?;
            w.place(e, f)?;
            w.at(e, draft.clone()).set(&Value::Int(1))?;
            Ok(e)
        })
        .unwrap();
    let durable_in_f = |db: &Osis| db.engine(|x| x.durable_groups_of(&e)).contains(&f);
    let s = Scope::Thing(e);
    db.write_with(|w| w.at(e, body.clone()).set(&Value::Int(1))).unwrap();
    assert!(durable_in_f(&db));
    db.undo(&s).unwrap().unwrap();
    assert!(db.groups_of(e).item_of == vec![f] && !durable_in_f(&db), "placed ephemerally again");
    assert!(db.get(e, body.clone()).unwrap().is_none() && db.get(e, draft.clone()).unwrap() == int(1) && db.knows(e), "the draft");
    assert!(db.created(e).unwrap().commit.is_some(), "the record stays durable");
    db.undo(&s).unwrap().unwrap();
    assert!(!db.knows(e) && db.groups_of(e).within.is_empty() && db.get(e, draft.clone()).unwrap().is_none(), "the draft's creation undone");
    assert_eq!(db.undo(&s).unwrap(), None);
    db.redo(&s).unwrap().unwrap();
    assert!(db.knows(e) && db.groups_of(e).item_of == vec![f] && !durable_in_f(&db) && db.get(e, draft.clone()).unwrap() == int(1));
    db.redo(&s).unwrap().unwrap();
    assert!(durable_in_f(&db) && db.get(e, body.clone()).unwrap() == int(1) && db.get(e, draft.clone()).unwrap() == int(1));
    assert_eq!(db.redo(&s).unwrap(), None);
    // undo the save again, then save anew: the placement converts
    db.undo(&s).unwrap().unwrap();
    assert!(!durable_in_f(&db));
    db.write_with(|w| w.at(e, body.clone()).set(&Value::Int(2))).unwrap();
    assert!(durable_in_f(&db) && db.groups_of(e).item_of == vec![f]);
    // and undoing that new save returns to the draft too
    db.undo(&s).unwrap().unwrap();
    assert!(!durable_in_f(&db) && db.groups_of(e).item_of == vec![f] && db.get(e, body).unwrap().is_none() && db.knows(e));
}

// notes/ephemeral.md Undo (undoing a save returns the draft): a draft with no content of its
// own (placed only) is known; so is it again after undoing its save; undoing its creation
// then deletes it (unknown, unplaced), redo brings it back known; `delete` deletes it
#[test]
fn undo_of_save_restores_an_empty_draft_spec_crdt_4_6() {
    let db = setup(10);
    let f = db.write_with(|w| { let f = w.create_durable(db.me())?; w.make_group(f)?; Ok(f) }).unwrap();
    let e = db.write_with(|w| { let e = w.create(db.me())?; w.place(e, f)?; Ok(e) }).unwrap();
    assert!(db.knows(e));
    db.write_with(|w| w.at(e, ak("/app/body")).set(&Value::Int(1))).unwrap();
    let s = Scope::Thing(e);
    db.undo(&s).unwrap().unwrap();
    assert!(db.knows(e) && db.groups_of(e).item_of == vec![f], "the draft again");
    db.undo(&s).unwrap().unwrap();
    assert!(!db.knows(e) && db.groups_of(e).within.is_empty(), "its creation undone");
    db.redo(&s).unwrap().unwrap();
    assert!(db.knows(e) && db.groups_of(e).item_of == vec![f]);
    db.write_with(|w| w.delete(e)).unwrap();
    assert!(!db.knows(e), "deleting the draft again: known");
    assert_eq!(db.groups_of(e).within, vec![], "deleting the draft again");
}

// spec/data-model.md §8: placing a durable thing into an ephemeral group is a durable add and
// persists the group then, so a durable thing is never placed ephemerally on purpose; an
// ephemeral placement of a durable thing was made while it was ephemeral (or restored by
// undoing its save), which is why any durable write of it converts it (`place_plan`)
#[test]
fn durable_thing_into_ephemeral_group_persists_it_spec_data_model_8() {
    let db = setup(11);
    let n = db.write_with(|w| { let n = w.create(db.me())?; w.at(n, ak("/app/body")).set(&Value::Int(1))?; Ok(n) }).unwrap();
    let g = db.write_with(|w| { let g = w.create(db.me())?; w.make_group(g)?; Ok(g) }).unwrap();
    assert!(db.created(g).unwrap().commit.is_none(), "the group is ephemeral");
    db.write_with(|w| w.place(n, g)).unwrap();
    assert!(db.created(g).unwrap().commit.is_some() && db.engine(|x| x.durable_groups_of(&n)).contains(&g), "placed durably, the group persisted");
}
