//! Undo, redo, revert and the commit query over ephemeral changes (notes/ephemeral.md API
//! delta, Local engine Undo; spec/crdt.md §4.6): an in-memory log of this session's own
//! ephemeral commits, the scope rule, mixed commits as one change, the history cap.

use osis::internals::CommitRaw as _;
use crate::common::TestWrites as _;
use osis::internals::Internals as _;
use crate::common::*;
use crate::common::CreateIn;
use osis::{CommitKind, CommitQuery, NotUndoableReason, Error, MemStore, Osis, Scope, Value};

fn setup(seed: u64) -> Osis {
    osis::internals::create(cfg(seed, MemStore::new(), &clock())).unwrap().0
}

fn int(n: i64) -> Option<Value> {
    Some(Value::Int(n))
}

// notes/ephemeral.md API delta (Undo): own ephemeral commits are changes (`Ephemeral` kind):
// undo and redo step through them on an ephemeral thing like through commits, including a
// register written twice and "absent before"; nothing reaches the store. spec/crdt.md §4.6
#[test]
fn undo_redo_ephemeral_thing_spec_crdt_4_6() {
    let db = setup(1);
    let k = ak("app:draft.0~");
    let mut w = db.write();
    let t = w.create().unwrap();
    w.commit().unwrap();
    let marks = || db.engine(|e| (e.commit_ids().len(), e.core.generation));
    let before = marks();
    db.commit_set(t, osis::DynamicAspectKey::untyped(k.clone()), &Value::Int(1)).unwrap();
    db.commit_set(t, osis::DynamicAspectKey::untyped(k.clone()), &Value::Int(2)).unwrap();
    let scope = Scope::Thing(t);
    let get = || db.at(t, osis::DynamicAspectKey::untyped(k.clone())).get().unwrap();
    let all = db.commits(&CommitQuery { scope: Some(scope.clone()), ..Default::default() }).unwrap();    assert_eq!(all.len(), 3, "the creation and two writes");
    assert!(all.iter().all(|e| e.kind == CommitKind::Ephemeral && e.in_effect && e.commit.id.commit().is_none()));
    let u = db.undo(&scope).unwrap().unwrap();
    assert!(u.id.commit().is_none());
    assert_eq!(get(), int(1));
    let found = db.commits(&CommitQuery { scope: Some(scope.clone()), reverts: Some(all[0].commit.id), ..Default::default() }).unwrap();
    assert_eq!(found.iter().map(|e| (e.commit.id, e.kind)).collect::<Vec<_>>(), vec![(u.id, CommitKind::Ephemeral)]);
    let target = db.commits(&CommitQuery { scope: Some(scope.clone()), reverted_by: Some(u.id), ..Default::default() }).unwrap();
    assert_eq!((target[0].commit.id, target[0].in_effect), (all[0].commit.id, false));
    db.undo(&scope).unwrap().unwrap();
    assert_eq!(get(), None, "absent before the first write");
    assert!(db.has_content(t).unwrap());
    db.undo(&scope).unwrap().unwrap();
    assert!(!db.has_content(t).unwrap(), "undoing the creation deletes");
    assert_eq!(db.undo(&scope).unwrap(), None);
    db.redo(&scope).unwrap().unwrap();
    assert!(db.has_content(t).unwrap() && get().is_none());
    db.redo(&scope).unwrap().unwrap();
    assert_eq!(get(), int(1));
    db.redo(&scope).unwrap().unwrap();
    assert_eq!(get(), int(2));
    assert_eq!(db.redo(&scope).unwrap(), None);
    db.undo(&scope).unwrap().unwrap();
    assert_eq!(get(), int(1));
    // a new change clears redo
    db.commit_set(t, osis::DynamicAspectKey::untyped(k.clone()), &Value::Int(5)).unwrap();
    assert_eq!(db.redo(&scope).unwrap(), None);
    db.undo(&scope).unwrap().unwrap();
    assert_eq!(get(), int(1));
    assert_eq!(marks(), before, "no commit, no store write");
    // revert by id; an id this session never logged is Invalid
    let newest = db.commits(&CommitQuery { scope: Some(scope.clone()), in_effect: Some(true), kinds: vec![CommitKind::Ephemeral], ..Default::default() }).unwrap()[0].commit.id;
    db.revert(newest).unwrap();
    let other = setup(2);
    let mut w = other.write();
    let x = w.create().unwrap();
    w.at(x, osis::DynamicAspectKey::untyped(k.clone())).set(&Value::Int(1)).unwrap();
    w.commit().unwrap();
    let oid = other.commits(&CommitQuery { kinds: vec![CommitKind::Ephemeral], ..Default::default() }).unwrap()[0].commit.id;
    assert!(matches!(db.revert(oid), Err(Error::Invalid(_))));
}

// notes/ephemeral.md API delta (Undo): Thing and Group scopes cover durable aspects and
// ephemeral things; an ephemeral aspect of a durable thing (a cursor) is in scope only when
// named by `Scope::Aspects`, so document undo never steps through cursor moves.
#[test]
fn thing_scope_skips_cursor_spec_crdt_4_6() {
    let db = setup(3);
    let text = ak("doc:text.0");
    let cursor = ak("doc:cursor.0~");
    let mut w = db.write();
    let d = w.create_durable(db.me()).unwrap();
    w.commit().unwrap();
    db.commit_set(d, osis::DynamicAspectKey::untyped(text.clone()), &Value::Str("a".into())).unwrap();
    db.commit_set(d, osis::DynamicAspectKey::untyped(cursor.clone()), &Value::Int(1)).unwrap();
    db.commit_set(d, osis::DynamicAspectKey::untyped(cursor.clone()), &Value::Int(2)).unwrap();
    let doc = Scope::Thing(d);
    assert!(db.commits(&CommitQuery { scope: Some(doc.clone()), ..Default::default() }).unwrap().iter().all(|e| e.kind != CommitKind::Ephemeral));
    db.undo(&doc).unwrap().unwrap();
    assert_eq!(db.at(d, osis::DynamicAspectKey::untyped(text.clone())).get().unwrap(), None, "the text change, not a cursor move");
    assert_eq!(db.at(d, osis::DynamicAspectKey::untyped(cursor.clone())).get().unwrap(), int(2));
    let cur = Scope::Aspects(vec![(d, ak("doc:cursor.0~"))]);
    db.undo(&cur).unwrap().unwrap();
    assert_eq!(db.at(d, osis::DynamicAspectKey::untyped(cursor.clone())).get().unwrap(), int(1));
    db.redo(&cur).unwrap().unwrap();
    assert_eq!(db.at(d, osis::DynamicAspectKey::untyped(cursor)).get().unwrap(), int(2));
}

// spec/crdt.md §4.6: a commit that keeps a draft placed in a group has a memory commit following it
// (the placement leaving `placed.0~`): undo takes both in one step, the draft back in the group in
// memory; redo keeps it again. The commit names the entry.
#[test]
fn keeping_a_draft_undone_in_one_step_spec_crdt_4_6() {
    let db = setup(4);
    let x = ak("t:x.0");
    let g = db.commit_with(|w| w.create_durable(db.me())).unwrap();
    let d = db.commit_with(|w| {
        let d = w.create()?;
        w.group(g).add(osis::Member::Item(d))?;
        Ok(d)
    })
    .unwrap();
    let mut w = db.write();
    w.at(d, osis::DynamicAspectKey::untyped(x.clone())).set(&Value::Int(1)).unwrap();
    let c = w.commit().unwrap().unwrap();
    assert!(c.id.commit().is_some());
    let durable = |db: &Osis| db.at(g, osis::internals::core_types::GROUP).get().unwrap().unwrap_or_default().items.contains(&d);
    let placed = |db: &Osis| db.at(g, osis::internals::core_types::PLACED).get().unwrap().unwrap_or_default().items.contains(&d);
    assert!(durable(&db) && !placed(&db));
    let scope = Scope::Thing(d);
    assert_eq!(db.commits(&CommitQuery { scope: Some(scope.clone()), ..Default::default() }).unwrap()[0].commit.id, c.id);
    let u = db.undo(&scope).unwrap().unwrap();
    assert!(u.id.commit().is_some(), "the revert has a durable commit");
    assert_eq!(db.at(d, osis::DynamicAspectKey::untyped(x.clone())).get().unwrap(), None);
    assert!(!durable(&db) && placed(&db), "back in the group in memory");
    db.redo(&scope).unwrap().unwrap();
    assert_eq!(db.at(d, osis::DynamicAspectKey::untyped(x)).get().unwrap(), int(1));
    assert!(durable(&db) && !placed(&db));
}

// notes/ephemeral.md API delta (Undo): a folder scope covers its durable item and its
// ephemeral draft; undo steps newest first across durable and ephemeral changes, redo back.
#[test]
fn mixed_scope_undo_order_spec_crdt_4_6() {
    let db = setup(5);
    let (body, draft) = (ak("t:body.0"), ak("t:draft.0~"));
    let (f, item) = db
        .commit_with(|w| {
            let f = w.create_durable(db.me())?;
            let item = w.create_durable(db.me())?;
            w.group(f).add(osis::Member::Item(item))?;
            Ok((f, item))
        })
        .unwrap();
    let e = db
        .commit_with(|w| {
            let e = w.create()?;
            w.group(f).add(osis::Member::Item(e))?;
            Ok(e)
        })
        .unwrap();
    db.commit_set(item, osis::DynamicAspectKey::untyped(body.clone()), &Value::Int(1)).unwrap();
    db.commit_set(e, osis::DynamicAspectKey::untyped(draft.clone()), &Value::Int(1)).unwrap();
    db.commit_set(item, osis::DynamicAspectKey::untyped(body.clone()), &Value::Int(2)).unwrap();
    db.commit_set(e, osis::DynamicAspectKey::untyped(draft.clone()), &Value::Int(2)).unwrap();
    let scope = Scope::Group(f);
    let state = || (db.at(item, osis::DynamicAspectKey::untyped(body.clone())).get().unwrap(), db.at(e, osis::DynamicAspectKey::untyped(draft.clone())).get().unwrap());
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
    let mut w = db.write();
    w.group(f).remove(osis::Member::Item(e)).unwrap();
    w.commit().unwrap();
    assert!(!db.groups_of(e).unwrap().within.contains(&f));
    db.undo(&scope).unwrap().unwrap();
    assert!(db.groups_of(e).unwrap().within.contains(&f));
    db.redo(&scope).unwrap().unwrap();
    assert!(!db.groups_of(e).unwrap().within.contains(&f));
}

// notes/ephemeral.md Bounds (`ephemeral_history`): past the cap the oldest ephemeral commits
// leave the log; undo reaching one is `NotUndoable{Compacted}` (nothing older instead), and a
// revert of it too.
#[test]
fn not_undoable_past_history_cap_spec_crdt_4_6() {
    let c = clock();
    let mut x = cfg(6, MemStore::new(), &c);
    x.ephemeral_undo_bytes = 8_000;
    let db = osis::internals::create(x).unwrap().0;
    let k = ak("app:n.0~");
    let t = db.commit_with(|w| w.create()).unwrap();
    let mut ids = Vec::new();
    for i in 0..40 {
        ids.push(db.write().tap(|w| w.at(t, osis::DynamicAspectKey::untyped(k.clone())).set(&Value::Int(i)).unwrap()).commit().unwrap().unwrap().id);
    }
    let scope = Scope::Thing(t);
    let logged = db.commits(&CommitQuery { scope: Some(scope.clone()), ..Default::default() }).unwrap().len();
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
    assert!(matches!(err, Error::NotUndoable { commit, reason: NotUndoableReason::ContentGone } if commit.commit().is_none()), "{err:?}");
    assert_eq!(db.revert(ids[0]), Err(Error::NotUndoable { commit: ids[0], reason: NotUndoableReason::ContentGone }));
    // at 0 no ephemeral change is undoable
    let mut x = cfg(7, MemStore::new(), &c);
    x.ephemeral_undo_bytes = 0;
    let db = osis::internals::create(x).unwrap().0;
    let mut w = db.write();
    let t = w.create().unwrap();
    w.commit().unwrap();
    db.commit_set(t, osis::DynamicAspectKey::untyped(k.clone()), &Value::Int(1)).unwrap();
    assert!(matches!(db.undo(&Scope::Thing(t)), Err(Error::NotUndoable { reason: NotUndoableReason::ContentGone, .. })));
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
    let draft = ak("app:draft.0~");
    let body = ak("app:body.0");
    let mut w = db.write();
    let f = w.create_durable(db.me()).unwrap();
    w.commit().unwrap();
    let mut w = db.write();
    let e = w.create().unwrap();
    w.group(f).add(osis::Member::Item(e)).unwrap();
    w.at(e, osis::DynamicAspectKey::untyped(draft.clone())).set(&Value::Int(1)).unwrap();
    w.commit().unwrap();
    let durable_in_f = |db: &Osis| db.engine(|x| x.durable_groups_of(&e)).contains(&f);
    let s = Scope::Thing(e);
    db.commit_set(e, osis::DynamicAspectKey::untyped(body.clone()), &Value::Int(1)).unwrap();
    assert!(durable_in_f(&db));
    db.undo(&s).unwrap().unwrap();
    assert!(db.groups_of(e).unwrap().item_of == vec![f] && !durable_in_f(&db), "placed ephemerally again");
    assert!(db.at(e, osis::DynamicAspectKey::untyped(body.clone())).get().unwrap().is_none() && db.at(e, osis::DynamicAspectKey::untyped(draft.clone())).get().unwrap() == int(1) && db.has_content(e).unwrap(), "the draft");
    assert!(db.created(e).unwrap().unwrap().id.is_some(), "the record stays durable");
    db.undo(&s).unwrap().unwrap();
    assert!(!db.has_content(e).unwrap() && db.groups_of(e).unwrap().within.is_empty() && db.at(e, osis::DynamicAspectKey::untyped(draft.clone())).get().unwrap().is_none(), "the draft's creation undone");
    assert_eq!(db.undo(&s).unwrap(), None);
    db.redo(&s).unwrap().unwrap();
    assert!(db.has_content(e).unwrap() && db.groups_of(e).unwrap().item_of == vec![f] && !durable_in_f(&db) && db.at(e, osis::DynamicAspectKey::untyped(draft.clone())).get().unwrap() == int(1));
    db.redo(&s).unwrap().unwrap();
    assert!(durable_in_f(&db) && db.at(e, osis::DynamicAspectKey::untyped(body.clone())).get().unwrap() == int(1) && db.at(e, osis::DynamicAspectKey::untyped(draft.clone())).get().unwrap() == int(1));
    assert_eq!(db.redo(&s).unwrap(), None);
    // undo the save again, then save anew: the placement converts
    db.undo(&s).unwrap().unwrap();
    assert!(!durable_in_f(&db));
    db.commit_set(e, osis::DynamicAspectKey::untyped(body.clone()), &Value::Int(2)).unwrap();
    assert!(durable_in_f(&db) && db.groups_of(e).unwrap().item_of == vec![f]);
    // and undoing that new save returns to the draft too
    db.undo(&s).unwrap().unwrap();
    assert!(!durable_in_f(&db) && db.groups_of(e).unwrap().item_of == vec![f] && db.at(e, osis::DynamicAspectKey::untyped(body)).get().unwrap().is_none() && db.has_content(e).unwrap());
}

// notes/ephemeral.md Undo (undoing a save returns the draft): a draft with no content of its
// own (placed only) is known; so is it again after undoing its save; undoing its creation
// then deletes it (unknown, unplaced), redo brings it back known; `delete` deletes it
#[test]
fn undo_of_save_restores_an_empty_draft_spec_crdt_4_6() {
    let db = setup(10);
    let mut w = db.write();
    let f = w.create_durable(db.me()).unwrap();
    w.commit().unwrap();
    let mut w = db.write();
    let e = w.create().unwrap();
    w.group(f).add(osis::Member::Item(e)).unwrap();
    w.commit().unwrap();
    assert!(db.has_content(e).unwrap());
    db.commit_set(e, osis::DynamicAspectKey::untyped(ak("app:body.0")), &Value::Int(1)).unwrap();
    let s = Scope::Thing(e);
    db.undo(&s).unwrap().unwrap();
    assert!(db.has_content(e).unwrap() && db.groups_of(e).unwrap().item_of == vec![f], "the draft again");
    db.undo(&s).unwrap().unwrap();
    assert!(!db.has_content(e).unwrap() && db.groups_of(e).unwrap().within.is_empty(), "its creation undone");
    db.redo(&s).unwrap().unwrap();
    assert!(db.has_content(e).unwrap() && db.groups_of(e).unwrap().item_of == vec![f]);
    let mut w = db.write();
    w.delete(e).unwrap();
    w.commit().unwrap();
    assert!(!db.has_content(e).unwrap(), "deleting the draft again: known");
    assert_eq!(db.groups_of(e).unwrap().within, vec![], "deleting the draft again");
}

// spec/data-model.md §8: placing a durable thing into an ephemeral group is a durable add and
// persists the group then, so a durable thing is never placed ephemerally on purpose; an
// ephemeral placement of a durable thing was made while it was ephemeral (or restored by
// undoing its save), which is why any durable write of it converts it (`place_plan`)
#[test]
fn durable_thing_into_ephemeral_group_persists_it_spec_data_model_8() {
    let db = setup(11);
    let mut w = db.write();
    let n = w.create().unwrap();
    w.at(n, osis::DynamicAspectKey::untyped(ak("app:body.0"))).set(&Value::Int(1)).unwrap();
    w.commit().unwrap();
    let mut w = db.write();
    let g = w.create().unwrap();
    w.commit().unwrap();
    assert!(db.created(g).unwrap().unwrap().id.is_none(), "the group is ephemeral");
    let mut w = db.write();
    w.group(g).add(osis::Member::Item(n)).unwrap();
    w.commit().unwrap();
    assert!(db.created(g).unwrap().unwrap().id.is_some() && db.engine(|x| x.durable_groups_of(&n)).contains(&g), "placed durably, the group persisted");
}

// spec/crdt.md §4.6 Expiry: a commit's `expires` overrides its keys' defaults, and its undo has no use
// for them: what the undo writes expires as what it copies back, so a commit that could be made can be
// undone and redone. Durable and ephemeral alike.
#[test]
fn undo_takes_no_key_default_spec_crdt_4_6() {
    let db = setup(30);
    db.register_schema("rv.osis", "version 1;\naspect app:d.0: int [expires: 30d];\naspect app:p.0: int;\naspect app:d.0~: int [expires: 30s];\naspect app:p.0~: int;").unwrap();
    let t = db.commit_with(|w| w.create_durable(db.me())).unwrap();
    for (x, y) in [("app:d.0", "app:p.0"), ("app:d.0~", "app:p.0~")] {
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
    let db = osis::internals::create(cfg(31, MemStore::new(), &c)).unwrap().0;
    let t = db.commit_with(|w| w.create_durable(db.me())).unwrap();
    for (x, y) in [("app:a.0", "app:b.0"), ("app:a.0~", "app:b.0~")] {
        let (a, b) = (osis::DynamicAspectKey::untyped(ak(x)), osis::DynamicAspectKey::untyped(ak(y)));
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
