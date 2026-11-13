//! Undo, redo and revert touch only kept history (spec/crdt.md §4.6, spec/commits.md §7,
//! notes/listener-design.md): whether an undo works, and what it writes, follows from the
//! history setting and the edit's age alone, durable and ephemeral alike, never from what a node
//! happens to hold.

use osis::internals::CommitRaw as _;
use crate::common::TestWrites as _;
use osis::internals::Internals as _;
use crate::common::*;
use crate::common::CreateIn;
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
        let t = w.create()?;
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

// spec/commits.md §7 (Kept history only; Tess): on an aspect no setting keeps, no
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

// spec/crdt.md §4.6: one edit undoes to one outcome whether the body it replaced is still held or
// was compacted into a snapshot: with history kept the value comes back either way, with none
// the undo is `NotUndoable` either way.
#[test]
fn undo_alike_held_or_compacted_spec_crdt_4_6() {
    for name in ["app:k.0", "app:n.0"] {
        let outcome = |compact: bool| {
            let db = setup(0);
            let t = kept_thing(&db);
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

// spec/commits.md §7 (Kept history only; Tess): what only takes away what it made
// (a list insert) undoes and redoes while the setting keeps it, and is refused once it leaves
// history by the setting's bound (the list is kept until a time `T`), its body still held: the
// setting decides, never compaction. With history a first register set undoes to absent and
// redoes.
#[test]
fn takings_undo_while_kept_spec_commits_7() {
    let c = clock();
    let db = osis::internals::create(cfg(0, MemStore::new(), &c)).unwrap();
    db.register_schema("undo.osis", SCHEMA).unwrap();
    let until = osis::History::Keep { until: osis::Time(T0 + 60_000), after_replaced: std::time::Duration::ZERO };
    let x = setting(&[("app:l.0", until), ("app:k.0", crate::common::DAY)]);
    let t = db.commit_with(|w| {
        let t = w.create()?;
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
    assert!(db.engine(|e| e.body_not_dropped(&late.raw(), &t, &la)), "held");
    assert_eq!(db.undo_target(&list), Err(gone(late)), "past T");
    assert_eq!(db.revert(late), Err(gone(late)));
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

// notes/ephemeral.md API (Undo): Thing and Group scopes cover durable aspects; an ephemeral
// aspect (a cursor) is in scope only when named by `Scope::Aspects`, so document undo never
// steps through cursor moves.
#[test]
fn thing_scope_skips_cursor_spec_crdt_4_6() {
    let db = setup(0);
    let (text, cursor) = (key(&db, "app:k.0"), key(&db, "app:ke+.0"));
    let mut w = db.write();
    let d = w.create_with_content(db.home()).unwrap();
    keeps(&mut w, d);
    w.commit().unwrap();
    db.commit_set(d, text.clone(), &Value::Int(1)).unwrap();
    db.commit_set(d, cursor.clone(), &Value::Int(1)).unwrap();
    db.commit_set(d, cursor.clone(), &Value::Int(2)).unwrap();
    let doc = Scope::Thing(d);
    assert!(db.writes(&doc, &CommitQuery::default()).unwrap().commits.iter().all(|e| !e.parts().any(|(_, a, _)| a.ephemeral())));
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
    let db = setup(0);
    let (body, draft) = (key(&db, "app:k.0"), key(&db, "app:ke+.0"));
    let (f, item) = db
        .commit_with(|w| {
            let f = w.create_with_content(db.home())?;
            let item = w.create_with_content(db.home())?;
            keeps(w, item);
            w.group(f).add(osis::Member::Item(item))?;
            Ok((f, item))
        })
        .unwrap();
    let e = db.commit_with(|w| { let e = w.create_in(db.me(), &[f])?; keeps(w, e); Ok(e) }).unwrap();
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

// spec/crdt.md §4.6, spec/commits.md §6: a commit's `expires` overrides its keys' defaults, and its undo has no use
// for them: what the undo writes expires as what it copies back, so a commit that could be made can be
// undone and redone. Durable and ephemeral alike.
#[test]
fn undo_takes_no_key_default_spec_crdt_4_6() {
    let db = setup(0);
    db.register_schema("rv.osis", "revision 1;\nexpires(30d) aspect app:d.0: int;\naspect app:p.0: int;\nexpires(30s) ephemeral aspect app:de+.0: int;\nephemeral aspect app:pe+.0: int;").unwrap();
    let t = db.commit_with(|w| { let t = w.create_with_content(db.home())?; keep_all(w, t); Ok(t) }).unwrap();
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
    let db = osis::internals::create(cfg(0, MemStore::new(), &c)).unwrap();
    db.register_schema("two.osis", "revision 1;\naspect app:a.0: int;\naspect app:b.0: int;\nephemeral aspect app:c+.0: int;\nephemeral aspect app:d+.0: int;").unwrap();
    let t = db.commit_with(|w| { let t = w.create_with_content(db.home())?; keep_all(w, t); Ok(t) }).unwrap();
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

// spec/commits.md §7: a memory commit forgotten here (an expiring write superseded by its
// author's next one vanishes, spec/sync.md §9) still counts as a part the undone write may have
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

// spec/commits.md §7: undoing a creation needs no setting on the groups it was created into: the
// deletion removes the thing from every group, so a membership write whose writes in effect in
// the group's state only list things the commit created needs no kept history, judged from that
// state, alike with the write's body held or compacted. One also adding an existing thing to such
// a group needs the group's setting, so it is `NotKept`, nothing written.
#[test]
fn creation_in_plain_group_undoes_spec_commits_7() {
    let group = ak("group.0");
    for compact in [false, true] {
        let db = setup(0);
        let n_key = key(&db, "app:n.0");
        let (g, e) = db.commit_with(|w| Ok((w.create()?, w.create()?))).unwrap();
        let n = db
            .commit_with(|w| {
                let n = w.create_in(db.me(), &[g])?;
                w.at(n, n_key.clone()).set(&Value::Int(1))?;
                Ok(n)
            })
            .unwrap();
        assert_eq!(db.members(g).unwrap(), vec![osis::Member::Item(n)]);
        if compact {
            let c = db.writes(&Scope::Thing(n), &osis::CommitQuery::default()).unwrap().commits[0].stamp.id;
            db.engine(|x| {
                x.snapshot(&g, &group)?;
                x.drop_body(&c.raw(), &g, &group)
            })
            .unwrap();
            assert!(!db.engine(|x| x.body_not_dropped(&c.raw(), &g, &group)), "compacted");
        }
        db.undo(&Scope::Thing(n)).unwrap().unwrap();
        assert_eq!(db.members(g).unwrap(), vec![], "gone from the group, compact {compact}");
        let of = db.groups_of(n).unwrap();
        assert!(of.item_of.is_empty() && of.subgroup_of.is_empty() && of.within.is_empty(), "{of:?}");
        assert_eq!(db.at(n, n_key.clone()).get().unwrap(), None, "and its content");
        let (m, c) = db
            .commit_with(|w| {
                let m = w.create_in(db.me(), &[g])?;
                w.group(g).add(osis::Member::Item(e))?;
                Ok(m)
            })
            .map(|m| (m, db.writes(&Scope::Thing(m), &osis::CommitQuery::default()).unwrap().commits[0].stamp.id))
            .unwrap();
        let marks = db.engine(|x| x.commit_ids().len());
        assert_eq!(db.undo(&Scope::Thing(m)), Err(gone(c)), "an existing member added too");
        assert_eq!(db.engine(|x| x.commit_ids().len()), marks, "nothing written");
        let mut want = vec![osis::Member::Item(e), osis::Member::Item(m)];
        want.sort_by_key(|x| match x { osis::Member::Item(t) | osis::Member::Subgroup(t) => *t });
        assert_eq!(db.members(g).unwrap(), want);
    }
}
