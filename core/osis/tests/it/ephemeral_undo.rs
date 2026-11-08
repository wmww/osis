//! Undo, redo, revert and the commit query over ephemeral changes (notes/ephemeral.md API
//! delta, Local engine Undo; spec/crdt.md §4.6): an in-memory log of this session's own
//! ephemeral commits, the scope rule, the history cap.

use osis::internals::CommitRaw as _;
use crate::common::TestWrites as _;
use osis::internals::Internals as _;
use crate::common::*;
use crate::common::CreateIn;
use osis::{CommitKind, CommitQuery, NotUndoableReason, Error, MemStore, Osis, Scope, Value};

fn setup(seed: u64) -> Osis {
    osis::internals::create(cfg(seed, MemStore::new(), &clock())).unwrap()
}

fn int(n: i64) -> Option<Value> {
    Some(Value::Int(n))
}

// notes/ephemeral.md API (Undo): own ephemeral commits are changes (`Ephemeral` kind):
// undo and redo step through them in an aspect scope like through commits, including a register
// written twice and a first write undone to absent; nothing reaches the store. spec/crdt.md §4.6
#[test]
fn undo_redo_ephemeral_spec_crdt_4_6() {
    let db = setup(1);
    let k = ak("app:draft+.0");
    let t = db.commit_with(|w| w.create()).unwrap();
    let marks = || db.engine(|e| (e.commit_ids().len(), e.core.generation));
    let before = marks();
    db.commit_set(t, osis::DynamicAspectKey::untyped(k.clone()), &Value::Int(1)).unwrap();
    db.commit_set(t, osis::DynamicAspectKey::untyped(k.clone()), &Value::Int(2)).unwrap();
    let scope = Scope::Aspects(vec![(t, k.clone())]);
    let get = || db.at(t, osis::DynamicAspectKey::untyped(k.clone())).get().unwrap();
    let all = db.commits(&CommitQuery { scope: Some(scope.clone()), ..Default::default() }).unwrap();
    assert_eq!(all.len(), 2, "two writes");
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
    assert_eq!(db.undo(&scope).unwrap(), None);
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
    let x = other.commit_with(|w| w.create()).unwrap();
    other.commit_set(x, osis::DynamicAspectKey::untyped(k.clone()), &Value::Int(1)).unwrap();
    let oid = other.commits(&CommitQuery { kinds: vec![CommitKind::Ephemeral], ..Default::default() }).unwrap()[0].commit.id;
    assert!(matches!(db.revert(oid), Err(Error::Invalid(_))));
}

// notes/ephemeral.md API (Undo): Thing and Group scopes cover durable aspects; an ephemeral
// aspect (a cursor) is in scope only when named by `Scope::Aspects`, so document undo never
// steps through cursor moves.
#[test]
fn thing_scope_skips_cursor_spec_crdt_4_6() {
    let db = setup(3);
    let text = ak("doc:text.0");
    let cursor = ak("doc:cursor+.0");
    let mut w = db.write();
    let d = w.create_with_content(db.me()).unwrap();
    w.commit().unwrap();
    db.commit_set(d, osis::DynamicAspectKey::untyped(text.clone()), &Value::Str("a".into())).unwrap();
    db.commit_set(d, osis::DynamicAspectKey::untyped(cursor.clone()), &Value::Int(1)).unwrap();
    db.commit_set(d, osis::DynamicAspectKey::untyped(cursor.clone()), &Value::Int(2)).unwrap();
    let doc = Scope::Thing(d);
    assert!(db.commits(&CommitQuery { scope: Some(doc.clone()), ..Default::default() }).unwrap().iter().all(|e| e.kind != CommitKind::Ephemeral));
    db.undo(&doc).unwrap().unwrap();
    assert_eq!(db.at(d, osis::DynamicAspectKey::untyped(text.clone())).get().unwrap(), None, "the text change, not a cursor move");
    assert_eq!(db.at(d, osis::DynamicAspectKey::untyped(cursor.clone())).get().unwrap(), int(2));
    let cur = Scope::Aspects(vec![(d, ak("doc:cursor+.0"))]);
    db.undo(&cur).unwrap().unwrap();
    assert_eq!(db.at(d, osis::DynamicAspectKey::untyped(cursor.clone())).get().unwrap(), int(1));
    db.redo(&cur).unwrap().unwrap();
    assert_eq!(db.at(d, osis::DynamicAspectKey::untyped(cursor)).get().unwrap(), int(2));
}

// notes/ephemeral.md API (Undo): an aspect scope over a durable and an ephemeral aspect: undo
// steps newest first across durable and ephemeral changes, redo back.
#[test]
fn mixed_scope_undo_order_spec_crdt_4_6() {
    let db = setup(5);
    let (body, draft) = (ak("t:body.0"), ak("t:draft+.0"));
    let (f, item) = db
        .commit_with(|w| {
            let f = w.create_with_content(db.me())?;
            let item = w.create_with_content(db.me())?;
            w.group(f).add(osis::Member::Item(item))?;
            Ok((f, item))
        })
        .unwrap();
    let e = db.commit_with(|w| w.create_in(db.me(), &[f])).unwrap();
    db.commit_set(item, osis::DynamicAspectKey::untyped(body.clone()), &Value::Int(1)).unwrap();
    db.commit_set(e, osis::DynamicAspectKey::untyped(draft.clone()), &Value::Int(1)).unwrap();
    db.commit_set(item, osis::DynamicAspectKey::untyped(body.clone()), &Value::Int(2)).unwrap();
    db.commit_set(e, osis::DynamicAspectKey::untyped(draft.clone()), &Value::Int(2)).unwrap();
    let scope = Scope::Aspects(vec![(item, body.clone()), (e, draft.clone())]);
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
}

// notes/ephemeral.md Bounds (`ephemeral_history`): past the cap the oldest ephemeral commits
// leave the log; undo reaching one is `NotUndoable{Compacted}` (nothing older instead), and a
// revert of it too.
#[test]
fn not_undoable_past_history_cap_spec_crdt_4_6() {
    let c = clock();
    let mut x = cfg(6, MemStore::new(), &c);
    x.ephemeral_undo_bytes = 8_000;
    let db = osis::internals::create(x).unwrap();
    let k = ak("app:n+.0");
    let t = db.commit_with(|w| w.create()).unwrap();
    let mut ids = Vec::new();
    for i in 0..40 {
        ids.push(db.write().tap(|w| w.at(t, osis::DynamicAspectKey::untyped(k.clone())).set(&Value::Int(i)).unwrap()).commit().unwrap().unwrap().id);
    }
    let scope = Scope::Aspects(vec![(t, k.clone())]);
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
    let db = osis::internals::create(x).unwrap();
    let t = db.commit_with(|w| w.create()).unwrap();
    db.commit_set(t, osis::DynamicAspectKey::untyped(k.clone()), &Value::Int(1)).unwrap();
    assert!(matches!(db.undo(&Scope::Aspects(vec![(t, k.clone())])), Err(Error::NotUndoable { reason: NotUndoableReason::ContentGone, .. })));
}

trait Tap: Sized {
    fn tap(mut self, f: impl FnOnce(&mut Self)) -> Self {
        f(&mut self);
        self
    }
}
impl Tap for osis::Write<'_> {}

// spec/crdt.md §4.6 Expiry: a commit's `expires` overrides its keys' defaults, and its undo has no use
// for them: what the undo writes expires as what it copies back, so a commit that could be made can be
// undone and redone. Durable and ephemeral alike.
#[test]
fn undo_takes_no_key_default_spec_crdt_4_6() {
    let db = setup(30);
    db.register_schema("rv.osis", "revision 1;\nexpires(30d) aspect app:d.0: int;\naspect app:p.0: int;\nexpires(30s) ephemeral aspect app:de+.0: int;\nephemeral aspect app:pe+.0: int;").unwrap();
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
    let t = db.commit_with(|w| w.create_with_content(db.me())).unwrap();
    for (x, y) in [("app:a.0", "app:b.0"), ("app:a+.0", "app:b+.0")] {
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
