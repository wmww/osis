//! The commit query, undo, redo, revert (notes/api.md Commits; spec/commits.md §7, spec/crdt.md §4.6).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis::internals::Exact as _;
use osis::internals::CommitRaw as _;
use crate::common::TestWrites as _;
use osis::internals::Internals as _;
use crate::common;
use common::*;
use crate::common::CreateIn;
use osis::{CommitId, CommitKind, CommitQuery, NotUndoableReason, Error, MemStore, Osis, Scope, Value};
use osis_sim::world::World;

// spec/commits.md §7, notes/api.md Commits: undo and redo walk this actor's own commits in
// scope; redo is an undo of the undo; a new undo after a redo undoes the redone change. A
// register edited twice undoes twice (spec/crdt.md §4.6: each undo restores the read before its
// commit), then redoes twice.
#[test]
fn undo_redo_cycle_spec_commits_7() {
    let db = db(1);
    let k = ak("t:x.0");
    let mut w = db.write();
    let t = w.create().unwrap();
    w.commit().unwrap();
    db.commit_set(t, osis::DynamicAspectKey::untyped(k.clone()), &Value::Int(1)).unwrap();
    db.commit_set(t, osis::DynamicAspectKey::untyped(k.clone()), &Value::Int(2)).unwrap();
    let scope = Scope::Aspects(vec![(t, k.clone())]);
    let get = || db.at(t, osis::DynamicAspectKey::untyped(k.clone())).get().unwrap();
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
    let scope = Scope::Thing(t);
    let (a, b) = (ak("t:a.0"), ak("t:b.0"));
    db.commit_set(t, osis::DynamicAspectKey::untyped(a.clone()), &Value::Int(1)).unwrap();
    db.commit_set(t, osis::DynamicAspectKey::untyped(b.clone()), &Value::Int(1)).unwrap();
    db.undo(&scope).unwrap().unwrap();
    db.undo(&scope).unwrap().unwrap();
    assert_eq!((db.at(t, osis::DynamicAspectKey::untyped(a.clone())).get().unwrap(), db.at(t, osis::DynamicAspectKey::untyped(b.clone())).get().unwrap()), (None, None));
    // another scope sees nothing to undo
    let other = Scope::Aspects(vec![(t, ak("t:other.0"))]);
    assert_eq!(db.undo(&other).unwrap(), None);
}

// notes/api.md Commits (decided): a new change clears the redo stack.
#[test]
fn new_commit_clears_redo_spec_commits_7() {
    let db = db(1);
    let (a, b) = (ak("t:a.0"), ak("t:b.0"));
    let mut w = db.write();
    let t = w.create().unwrap();
    w.commit().unwrap();
    db.commit_set(t, osis::DynamicAspectKey::untyped(a.clone()), &Value::Int(1)).unwrap();
    let scope = Scope::Thing(t);
    db.undo(&scope).unwrap().unwrap();
    db.commit_set(t, osis::DynamicAspectKey::untyped(b.clone()), &Value::Int(1)).unwrap();
    assert_eq!(db.redo(&scope).unwrap(), None);
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(a)).get().unwrap(), None);
    // undo then redo still pairs up after the new change
    db.undo(&scope).unwrap().unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(b.clone())).get().unwrap(), None);
    db.redo(&scope).unwrap().unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(b)).get().unwrap(), Some(Value::Int(1)));
}

// spec/commits.md §7: when the newest commit's body was dropped (as covered by a snapshot), undo
// reports it and never undoes an older change instead.
#[test]
fn undo_blocked_by_dropped_body_spec_commits_7() {
    let db = db(1);
    let (a, b) = (ak("t:a.0"), ak("t:b.0"));
    let mut w = db.write();
    let t = w.create().unwrap();
    w.commit().unwrap();
    db.commit_set(t, osis::DynamicAspectKey::untyped(a.clone()), &Value::Int(1)).unwrap();
    let newest = commit_with(&db, |w| w.at(t, osis::DynamicAspectKey::untyped(b.clone())).set(&Value::Int(1))).id.commit().unwrap();
    db.engine(|e| {
        e.snapshot(&t, &b)?;
        e.drop_body(&newest, &t, &b)
    })
    .unwrap();
    assert_eq!(db.undo(&Scope::Thing(t)), Err(Error::NotUndoable { commit: osis::CommitId::from(newest), reason: NotUndoableReason::ContentGone }));
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(a)).get().unwrap(), Some(Value::Int(1)));
    assert_eq!(db.revert(osis::CommitId::from(newest)), Err(Error::NotUndoable { commit: osis::CommitId::from(newest), reason: NotUndoableReason::ContentGone }));
}

// notes/engine.md: an undo mutation carries nothing else.
#[test]
fn undo_mutation_alone_spec_commits_7() {
    let db = db(1);
    let mut w = db.write();
    let t = w.create_with_content(db.me()).unwrap();
    let c = w.commit().unwrap().unwrap().id.commit().unwrap();
    let mut m = osis::internals::node::Mutation::new();
    m.undo(c).set(t, &ak("t:x.0"), &Value::Int(1)).unwrap();
    assert!(matches!(db.engine(|e| e.commit(m)), Err(osis::internals::node::Error::Misuse(_))));
}

// notes/api.md Commits: the query lists everyone's commits in scope with their relations; a
// change whose body was dropped is `dropped`, never a silent no-op; revert reverts any commit
// this node may write.
#[test]
fn query_relations_spec_crdt_4_6() {
    let db = db(1);
    let (k, j) = (ak("t:x.0"), ak("t:y.0"));
    let mut w = db.write();
    let g = w.create().unwrap();
    let t = w.create_in(db.me(), &[g]).unwrap();
    w.commit().unwrap();
    let c1 = commit_with(&db, |w| w.at(t, osis::DynamicAspectKey::untyped(k.clone())).set(&Value::Int(1)));
    let mut w = db.write();
    w.act_as(db.node());
    w.at(t, osis::DynamicAspectKey::untyped(j.clone())).set(&Value::Int(5)).unwrap();
    let c2 = w.commit().unwrap().unwrap();
    // the node's commit is not me's to undo, but revert reverts it
    let u = db.revert(c2.id).unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(j.clone())).get().unwrap(), None);
    let all = CommitQuery { scope: Some(Scope::Group(g)), ..Default::default() };
    let h = db.commits(&all).unwrap();
    let entry = |c: osis::internals::RawCommitId| h.iter().find(|e| e.commit.id == osis::CommitId::from(c)).unwrap().clone();
    assert!(!entry(c2.id.commit().unwrap()).in_effect);
    assert_eq!(entry(c2.id.commit().unwrap()).reverted_by, vec![u.id]);
    assert!(entry(u.id.commit().unwrap()).in_effect && entry(c1.id.commit().unwrap()).in_effect);
    assert_eq!((entry(u.id.commit().unwrap()).kind, entry(u.id.commit().unwrap()).reverts), (CommitKind::Revert, Some(c2.id)));
    assert_eq!(entry(c1.id.commit().unwrap()).kind, CommitKind::Content);
    assert_eq!(h.first().map(|e| e.commit.id), Some(u.id));
    let paged = db.commits(&CommitQuery { after: Some(u.id), limit: Some(1), ..all.clone() }).unwrap();
    assert_eq!(paged.len(), 1);
    assert_eq!(paged[0].commit.id, h[1].commit.id);
    // purge drops c1's body
    let mut w = db.write();
    w.at(t, osis::DynamicAspectKey::untyped(k.clone())).purge(osis::Purge::All).unwrap();
    w.commit().unwrap();
    let h = db.commits(&CommitQuery { scope: Some(Scope::Aspects(vec![(t, k.clone())])), ..Default::default() }).unwrap();
    assert!(h.iter().find(|e| e.commit.id == c1.id).unwrap().content_gone);
    assert!(db.revert(osis::CommitId::from(osis::internals::RawCommitId([7; 32]))).is_err());
}

// notes/api.md Commits: each filter of the query, alone; results newest first.
#[test]
fn query_filters_api_commits() {
    let c = clock();
    let db = osis::internals::create(cfg(1, MemStore::new(), &c)).unwrap();
    let (k, j) = (ak("t:x.0"), ak("t:y.0"));
    // made acting for the account (a record alone would act for the node)
    let t = db.commit_with(|w| w.create_with_content(db.me())).unwrap();
    let c1 = commit_with(&db, |w| w.at(t, osis::DynamicAspectKey::untyped(k.clone())).set(&Value::Int(1)));
    c.advance(1);
    let mut w = db.write();
    w.act_as(db.node());
    w.at(t, osis::DynamicAspectKey::untyped(j.clone())).set(&Value::Int(5)).unwrap();
    let c2 = w.commit().unwrap().unwrap();
    c.advance(1);
    let c3 = commit_with(&db, |w| w.at(t, osis::DynamicAspectKey::untyped(k.clone())).set(&Value::Int(2)));
    let u3 = db.undo(&Scope::Thing(t)).unwrap().unwrap();
    let ids = |q: CommitQuery| db.commits(&q).unwrap().into_iter().map(|e| e.commit.id.commit().unwrap()).collect::<Vec<_>>();
    let base = || CommitQuery { scope: Some(Scope::Thing(t)), ..Default::default() };
    let everything = ids(base());
    assert_eq!(everything[..4], [u3.id.commit().unwrap(), c3.id.commit().unwrap(), c2.id.commit().unwrap(), c1.id.commit().unwrap()]);
    assert!(ids(CommitQuery::default()).starts_with(&everything[..4]), "no scope: every held commit");
    assert_eq!(ids(CommitQuery { scope: Some(Scope::Aspects(vec![(t, j.clone())])), ..base() }), vec![c2.id.commit().unwrap()]);
    assert_eq!(ids(CommitQuery { actors: vec![db.node()], ..base() }), vec![c2.id.commit().unwrap()]);
    assert!(!ids(CommitQuery { actors: vec![db.me()], ..base() }).contains(&c2.id.commit().unwrap()));
    assert_eq!(ids(CommitQuery { kinds: vec![CommitKind::Revert], ..base() }), vec![u3.id.commit().unwrap()]);
    assert_eq!(ids(CommitQuery { kinds: vec![CommitKind::Content], limit: Some(2), ..base() }), vec![c3.id.commit().unwrap(), c2.id.commit().unwrap()]);
    assert_eq!(ids(CommitQuery { reverts: Some(c3.id), ..base() }), vec![u3.id.commit().unwrap()]);
    assert_eq!(ids(CommitQuery { reverted_by: Some(u3.id), ..base() }), vec![c3.id.commit().unwrap()]);
    assert_eq!(ids(CommitQuery { in_effect: Some(false), ..base() }), vec![c3.id.commit().unwrap()]);
    assert_eq!(ids(CommitQuery { since: Some(c2.written), until: Some(c3.written), ..base() }), vec![c2.id.commit().unwrap()]);
    assert_eq!(ids(CommitQuery { after: Some(c3.id), kinds: vec![CommitKind::Content], limit: Some(1), ..base() }), vec![c2.id.commit().unwrap()]);
    assert!(db.commits(&CommitQuery { after: Some(osis::internals::RawCommitId([7; 32]).into()), ..base() }).is_err());
    let e = &db.commits(&CommitQuery { limit: Some(1), ..base() }).unwrap()[0];
    assert_eq!((e.commit.actor, e.commit.node, e.commit.ts()), (db.me(), db.node(), u3.ts()));
    assert_eq!(e.aspects, vec![(t, k.clone())]);
}

/// Two nodes of one account, paired locally; commits travel by `deliver`.
fn two_nodes() -> (Osis, Osis) {
    let c = clock();
    let a = osis::internals::create(cfg(1, MemStore::new(), &c)).unwrap();
    let j = osis::internals::pair(cfg(2, MemStore::new(), &c), &a.pair_offer().unwrap()).unwrap();
    let (_, reply) = a.pair_accept(j.request()).unwrap();
    let b = j.finish(&reply).unwrap();
    (a, b)
}

fn sync2(a: &Osis, b: &Osis) {
    deliver(a, b);
    deliver(b, a);
}

// notes/api.md Commits: undo and redo act on the actor's commits, whichever node made them:
// node B undoes A's change, A redoes B's undo, B undoes the redo; a revert made on one node
// is found by the other with the same query; a new change on one node clears redo on both.
#[test]
fn undo_redo_across_nodes_spec_commits_7() {
    let (da, db) = two_nodes();
    let k = ak("t:x.0");
    let t = da.commit_with(|w| w.create()).unwrap();
    let c1 = commit_with(&da, |w| w.at(t, osis::DynamicAspectKey::untyped(k.clone())).set(&Value::Int(1)));
    sync2(&da, &db);
    let get = |d: &Osis| d.at(t, osis::DynamicAspectKey::untyped(k.clone())).get().unwrap();
    assert_eq!(get(&db), Some(Value::Int(1)));
    let scope = Scope::Thing(t);
    let u = db.undo(&scope).unwrap().unwrap();
    assert_eq!(get(&db), None);
    sync2(&da, &db);
    assert_eq!(get(&da), None);
    let found = da.commits(&CommitQuery { reverts: Some(c1.id.commit().unwrap().into()), ..Default::default() }).unwrap();
    assert_eq!(found.iter().map(|e| (e.commit.id, e.commit.node)).collect::<Vec<_>>(), vec![(u.id, db.node())]);
    let r = da.redo(&scope).unwrap().unwrap();
    assert_eq!(get(&da), Some(Value::Int(1)));
    sync2(&da, &db);
    assert_eq!(get(&db), Some(Value::Int(1)));
    assert_eq!(db.commits(&CommitQuery { reverts: Some(u.id.commit().unwrap().into()), ..Default::default() }).unwrap()[0].commit.id, r.id);
    assert_eq!(db.redo(&scope).unwrap(), None, "no undo in effect");
    db.undo(&scope).unwrap().unwrap();
    assert_eq!(get(&db), None);
    sync2(&da, &db);
    assert_eq!(get(&da), None);
    // a new change on A clears redo on B too
    commit_with(&da, |w| w.at(t, osis::DynamicAspectKey::untyped(ak("t:y.0"))).set(&Value::Int(3)));
    sync2(&da, &db);
    assert_eq!(db.redo(&scope).unwrap(), None);
    assert_eq!(get(&db), None);
}

// notes/api.md Commits: another actor's revert of my change is found with the same query; my
// undo skips the commit it reverted; for its author the revert is an undo: redo reverts it.
#[test]
fn find_another_actors_revert_api_commits() {
    let mut w = World::new();
    let host = w.add_host();
    let alice = crate::scenario::account(&mut w, 1, host);
    let bob = crate::scenario::account(&mut w, 2, host);
    let b = crate::scenario::introduce(&mut w, &alice, &bob);
    let k = ak("t:x.0");
    let t = alice
        .commit_with(|wr| {
            let t = wr.create()?;
            Ok(t)
        })
        .unwrap();
    alice.sync(t, &[]).unwrap();
    alice.grant(t, b, osis::Role::Write, osis::GrantOpts::default()).unwrap();
    w.run();
    let c = commit_with(&alice, |wr| wr.at(t, osis::DynamicAspectKey::untyped(k.clone())).set(&Value::Int(1)));
    w.run();
    assert_eq!(bob.at(t, osis::DynamicAspectKey::untyped(k.clone())).get().unwrap(), Some(Value::Int(1)));
    let r = bob.revert(c.id).unwrap();
    w.run();
    assert_eq!(alice.at(t, osis::DynamicAspectKey::untyped(k.clone())).get().unwrap(), None);
    let found = alice.commits(&CommitQuery { reverts: Some(c.id.commit().unwrap().into()), ..Default::default() }).unwrap();
    assert_eq!(found.iter().map(|e| (e.commit.id, e.commit.actor)).collect::<Vec<_>>(), vec![(r.id, bob.me())]);
    let mine = alice.commits(&CommitQuery { scope: Some(Scope::Thing(t)), actors: vec![alice.me()], kinds: vec![CommitKind::Content], ..Default::default() }).unwrap();
    assert!(mine.iter().any(|e| e.commit.id == c.id && !e.in_effect && e.reverted_by == vec![r.id]));
    assert_eq!(alice.undo(&Scope::Aspects(vec![(t, k.clone())])).unwrap(), None, "alice's change is out of effect");
    // bob's revert is a revert: his undo skips it, his redo reverts it
    assert_eq!(bob.undo(&Scope::Thing(t)).unwrap(), None, "bob made no change");
    bob.redo(&Scope::Thing(t)).unwrap().unwrap();
    w.run();
    assert_eq!(alice.at(t, osis::DynamicAspectKey::untyped(k)).get().unwrap(), Some(Value::Int(1)));
}

// notes/api.md Attribution, spec/permissions.md §5.2: the API reports only verifiable authorship.
// B holds A's signed change: history lists it with A's node and `ts`. C holds only A's snapshot
// of the aspect: the value reads the same, its watch reports the commit as the snapshot's (its
// author, ID and `ts`), and its history claims nothing for the commit it never held.
#[test]
fn snapshot_only_attribution_api_history() {
    use osis::Origin;
    let (a, b, c) = (db(1), db(2), db(3));
    let k = ak("t:x.0");
    let t = a.commit_with(|w| w.create_with_content(a.me())).unwrap();
    deliver(&a, &b);
    deliver(&a, &c);
    let done = commit_with(&a, |w| w.at(t, osis::DynamicAspectKey::untyped(k.clone())).set(&Value::Int(7)));
    let snap = a.engine(|e| e.snapshot(&t, &k)).unwrap().unwrap();
    let snap_ts = a.engine(|e| e.header(&snap)).unwrap().ts;
    assert!(snap_ts > done.ts());
    deliver(&a, &b);
    let (tx, rx) = std::sync::mpsc::channel();
    let _s = c.at(t, osis::DynamicAspectKey::untyped(k.clone())).on_change(move |_, ch| tx.send(ch).unwrap()).unwrap();
    assert_eq!(recv(&rx).origin, Origin::Initial);
    let pks = a.engine(|e| e.commit_ids().iter().filter(|id| **id != done.id.commit().unwrap()).filter_map(|id| e.package(id).unwrap()).collect::<Vec<_>>());
    for pk in pks {
        c.engine(|e| e.ingest(&pk.bytes, pk.blobs.clone()).unwrap());
    }
    let ch = recv(&rx);
    assert_eq!(ch.value, Ok(Some(Value::Int(7))));
    assert!(matches!(ch.origin, Origin::Remote(i) if i.id == osis::CommitId::from(snap) && i.node == a.node() && i.ts() == snap_ts), "{:?}", ch.origin);
    let q = CommitQuery { scope: Some(Scope::Thing(t)), ..Default::default() };
    let hb = b.commits(&q).unwrap();
    assert!(hb.iter().any(|e| e.commit.id == done.id && e.commit.node == a.node() && e.commit.ts() == done.ts()), "{hb:?}");
    let hc = c.commits(&q).unwrap();
    assert!(hc.iter().all(|e| e.commit.id != done.id && e.commit.ts() != done.ts()), "{hc:?}");
    assert!(hc.iter().any(|e| e.commit.id == osis::CommitId::from(snap) && e.kind == CommitKind::Snapshot), "the snapshot as itself: {hc:?}");
}

const DOC_SCHEMA: &str = "revision 1;\naspect x:doc.0: struct { name 0: string, tags 1: set<string>, extra 2: enum { none 0, some 1 (struct { notes 0: set<string> }) }, items 3: list<string> };\n";

fn field(id: u64) -> osis::Step {
    osis::Step::Field(id)
}

// spec/crdt.md §4.6 (restores the prior read): undoing the first write into a spot that did not
// exist (a struct field's set, a set in an enum payload, a list) makes it absent again, so the
// read equals the read before; another's write into it already held when undoing stays.
#[test]
fn exact_undo_spec_crdt_4_6() {
    let (a, b) = two_nodes();
    for d in [&a, &b] {
        d.register_schema("doc.osis", DOC_SCHEMA).unwrap();
    }
    let doc = ak("x:doc.0");
    let t = a.commit_with(|w| w.create()).unwrap();
    a.commit_with(|w| {
        w.at(t, osis::DynamicAspectKey::untyped(doc.clone())).path(osis::Path(vec![field(0)])).set(&"n".to_string())?;
        w.at(t, osis::DynamicAspectKey::untyped(doc.clone())).path(osis::Path(vec![field(2)])).set(&Value::Enum(1, Some(Box::new(Value::Map(Default::default())))))
    })
    .unwrap();
    sync2(&a, &b);
    let before = a.at(t, osis::DynamicAspectKey::untyped(doc.clone())).get().unwrap();
    let scope = Scope::Thing(t);
    let spots: [(&str, osis::Path); 3] = [
        ("struct field set", osis::Path(vec![field(1)])),
        ("enum payload set", osis::Path(vec![field(2), osis::Step::Case(1), field(0)])),
        ("list", osis::Path(vec![field(3)])),
    ];
    let write = |d: &Osis, p: &osis::Path, item: &str| {
        let item = item.to_string();
        let key = d.aspect_key("x:doc.0").unwrap();
        d.commit_with(|w| if p.0.len() == 1 && p.0[0] == field(3) { w.at(t, key.clone()).path(p.clone()).splice(0..0, &[item]) } else { w.at(t, key.clone()).path(p.clone()).add(&item) }).unwrap();
    };
    for (name, p) in &spots {
        write(&a, p, "x");
        assert_ne!(a.at(t, osis::DynamicAspectKey::untyped(doc.clone())).get().unwrap(), before, "{name}");
        a.undo(&scope).unwrap().unwrap();
        assert_eq!(a.at(t, osis::DynamicAspectKey::untyped(doc.clone())).get().unwrap(), before, "{name}");
        // seen: b's write is held when a undoes, so only a's write goes
        sync2(&a, &b);
        write(&b, p, "y");
        sync2(&a, &b);
        let b_only = a.at(t, osis::DynamicAspectKey::untyped(doc.clone())).get().unwrap();
        write(&a, p, "x");

        a.undo(&scope).unwrap().unwrap();
        assert_eq!(a.at(t, osis::DynamicAspectKey::untyped(doc.clone())).get().unwrap(), b_only, "{name}: b's held write stays");
        // back to the start for the next spot: b undoes its write (a's undone write's
        // tombstone carries no value, so it does not block the reset)
        sync2(&a, &b);
        b.undo(&scope).unwrap().unwrap();
        sync2(&a, &b);
        assert_eq!(a.at(t, osis::DynamicAspectKey::untyped(doc.clone())).get().unwrap(), before, "{name}");
    }
}


/// What `next` picks in `scope`.
fn next(db: &Osis, scope: &Scope, redo: bool) -> Option<CommitId> {
    let e = if redo { db.redo_target(scope) } else { db.undo_target(scope) };
    e.unwrap().map(|e| e.commit.id)
}

/// Undo (redo) in `scope`, checking it reverts what `next` reported.
fn step(db: &Osis, scope: &Scope, redo: bool) -> Option<CommitId> {
    let want = next(db, scope, redo);
    let got = match redo {
        false => db.undo(scope),
        true => db.redo(scope),
    }
    .unwrap()
    .map(|c| c.id);
    match (want, got) {
        (Some(w), Some(g)) => assert_eq!(db.commits(&CommitQuery { reverted_by: Some(g), ..Default::default() }).unwrap().iter().map(|e| e.commit.id).collect::<Vec<_>>(), vec![w], "reverts what next reported"),
        (None, None) => {}
        x => panic!("next and the step disagree: {x:?}"),
    }
    got
}

// spec/crdt.md §4.6 Undoing a creation, notes/api.md Commits: undoing the commit that created a
// thing deletes it, its memberships in every group included (one made later in another group,
// and a subgroup edge); redo brings it back with its content and memberships. `next` reports the
// change each step then reverts.
#[test]
fn undo_of_creation_deletes_spec_crdt_4_6() {
    let db = db(1);
    let (x, y) = (ak("t:x.0"), ak("t:y.0"));
    let mk = |db: &Osis| db.commit_with(|w| w.create_with_content(db.me())).unwrap();
    let (f, f2, f3) = (mk(&db), mk(&db), mk(&db));
    let t = db.commit_with(|w| { let t = w.create_in(db.me(), &[f])?; w.at(t, osis::DynamicAspectKey::untyped(x.clone())).set(&Value::Int(1))?; Ok(t) }).unwrap();
    let created = db.created(t).unwrap().unwrap().id;
    db.commit_with(|w| { w.group(f2).add(osis::Member::Item(t))?; w.group(f3).add(osis::Member::Subgroup(t)) }).unwrap();
    let edit = commit_with(&db, |w| w.at(t, osis::DynamicAspectKey::untyped(y.clone())).set(&Value::Int(2))).id;
    let s = Scope::Thing(t);
    assert_eq!(next(&db, &s, true), None);
    assert_eq!(next(&db, &s, false), Some(edit));
    step(&db, &s, false).unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(y.clone())).get().unwrap(), None);
    assert_eq!(next(&db, &s, false), Some(created));
    step(&db, &s, false).unwrap();
    let gs = db.groups_of(t).unwrap();
    assert!(!db.has_content(t).unwrap() && gs.item_of.is_empty() && gs.subgroup_of.is_empty() && db.at(t, osis::DynamicAspectKey::untyped(x.clone())).get().unwrap().is_none(), "deleted: {gs:?}");
    assert_eq!(next(&db, &s, false), None);
    step(&db, &s, true).unwrap();
    let gs = db.groups_of(t).unwrap();
    assert!(db.has_content(t).unwrap() && db.at(t, osis::DynamicAspectKey::untyped(x.clone())).get().unwrap() == Some(Value::Int(1)));
    let mut items = gs.item_of;
    items.sort();
    let mut want = vec![f, f2];
    want.sort();
    assert_eq!((items, gs.subgroup_of), (want, vec![f3]));
    step(&db, &s, true).unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(y.clone())).get().unwrap(), Some(Value::Int(2)));
    assert_eq!(next(&db, &s, true), None);
    // reverting the creation directly, with a later commit in effect, deletes too (the later
    // content goes with it), and reverting that revert restores everything
    let r = db.revert(created).unwrap();
    assert!(!db.has_content(t).unwrap() && db.at(t, osis::DynamicAspectKey::untyped(y.clone())).get().unwrap().is_none() && db.groups_of(t).unwrap().within.is_empty());
    db.revert(r.id).unwrap();
    assert!(db.at(t, osis::DynamicAspectKey::untyped(x)).get().unwrap() == Some(Value::Int(1)) && db.at(t, osis::DynamicAspectKey::untyped(y)).get().unwrap() == Some(Value::Int(2)) && db.groups_of(t).unwrap().within.len() == 2);
}

// notes/ephemeral.md API (Undo), spec/crdt.md §4.6: undoing the commit that created a thing
// deletes it, its ephemeral aspects and its memberships in every group too; redo brings it back
// in its groups, its ephemeral values dropped (notes/ephemeral.md Deletion).
#[test]
fn undo_of_creation_resets_ephemeral_aspects_spec_crdt_4_6() {
    let db = db(2);
    let k = ak("app:draft+.0");
    let mk = |db: &Osis| db.commit_with(|w| w.create_with_content(db.me())).unwrap();
    let (f, f2) = (mk(&db), mk(&db));
    let e = db
        .commit_with(|w| {
            let e = w.create_with_content(db.me())?;
            w.group(f).add(osis::Member::Item(e))?;
            Ok(e)
        })
        .unwrap();
    db.commit_set(e, osis::DynamicAspectKey::untyped(k.clone()), &Value::Int(1)).unwrap();
    let mut w = db.write();
    w.group(f2).add(osis::Member::Item(e)).unwrap();
    w.commit().unwrap();
    let sorted = |mut v: Vec<osis::Tid>| {
        v.sort();
        v
    };
    assert_eq!(sorted(db.groups_of(e).unwrap().item_of), sorted(vec![f, f2]));
    let s = Scope::Thing(e);
    // the membership in f2 is a write of f2 and the ephemeral write is no durable aspect: outside
    // the thing's scope, so undo picks the creation
    let picked = next(&db, &s, false).unwrap();
    assert_eq!(picked, db.created(e).unwrap().unwrap().id);
    step(&db, &s, false).unwrap();
    assert!(!db.has_content(e).unwrap() && db.groups_of(e).unwrap().item_of.is_empty() && db.at(e, osis::DynamicAspectKey::untyped(k.clone())).get().unwrap().is_none());
    assert_eq!(step(&db, &s, false), None);
    step(&db, &s, true).unwrap();
    assert!(db.has_content(e).unwrap() && db.at(e, osis::DynamicAspectKey::untyped(k)).get().unwrap().is_none());
    assert_eq!(sorted(db.groups_of(e).unwrap().item_of), sorted(vec![f, f2]));
}

// notes/api.md Commits: `next` reports what undo and redo would revert, in a thing and in a
// broader scope; a new change clears what redo would revert; `next` needs a scope.
#[test]
fn next_reports_what_undo_and_redo_revert_api_commits() {
    let db = db(3);
    let k = ak("t:x.0");
    let f = db.commit_with(|w| { let g = w.create_with_content(db.me())?; Ok(g) }).unwrap();
    let in_f = |w: &mut osis::Write<'_>| -> osis::Result<osis::Tid> {
        let t = w.create_with_content(db.me())?;
        w.group(f).add(osis::Member::Item(t))?;
        Ok(t)
    };
    let (a, b) = db.commit_with(|w| Ok((in_f(w)?, in_f(w)?))).unwrap();
    let ca = commit_with(&db, |w| w.at(a, osis::DynamicAspectKey::untyped(k.clone())).set(&Value::Int(1))).id;
    let cb = commit_with(&db, |w| w.at(b, osis::DynamicAspectKey::untyped(k.clone())).set(&Value::Int(1))).id;
    let (sa, sf) = (Scope::Thing(a), Scope::Group(f));
    assert_eq!((next(&db, &sa, false), next(&db, &sf, false)), (Some(ca), Some(cb)));
    let u = step(&db, &sa, false).unwrap();
    assert_eq!((next(&db, &sa, true), next(&db, &sf, true)), (Some(u), Some(u)));
    // the group's newest change is still b's, in effect
    assert_eq!(next(&db, &sf, false), Some(cb));
    // a new change in the group clears its redo, not the thing's
    let cb2 = commit_with(&db, |w| w.at(b, osis::DynamicAspectKey::untyped(k.clone())).set(&Value::Int(2))).id;
    assert_eq!((next(&db, &sf, true), next(&db, &sa, true)), (None, Some(u)));
    assert_eq!(step(&db, &sf, true), None);
    assert_eq!(next(&db, &sf, false), Some(cb2));
    step(&db, &sa, true).unwrap();
    assert_eq!(db.at(a, osis::DynamicAspectKey::untyped(k)).get().unwrap(), Some(Value::Int(1)));
}

// spec/crdt.md §4.6 Undoing a creation, shared: the undo of a creation reaches the other
// holder (deleted there), redo restores it there; a writer (not admin) may revert another's
// creation of a thing it may write; reverting the creation of a thing it may not write is
// `Permission` and changes nothing (never a partial revert: removed but not deleted).
#[test]
fn undo_of_creation_shared_spec_crdt_4_6() {
    let mut w = World::new();
    let host = w.add_host();
    let alice = crate::scenario::account(&mut w, 1, host);
    let bob = crate::scenario::account(&mut w, 2, host);
    let b = crate::scenario::introduce(&mut w, &alice, &bob);
    let x = ak("t:x.0");
    let g = alice.commit_with(|wr| { let g = wr.create()?; Ok(g) }).unwrap();
    alice.sync(g, &[]).unwrap();
    alice.grant(g, b, osis::Role::Write, osis::GrantOpts::default()).unwrap();
    w.run();
    let mk = |admin: osis::Tid| alice.commit_with(|wr| { let t = wr.create_in(admin, &[g])?; wr.at(t, osis::DynamicAspectKey::untyped(x.clone())).set(&Value::Int(1))?; Ok(t) }).unwrap();
    let t = mk(g);
    w.run();
    assert_eq!(bob.at(t, osis::DynamicAspectKey::untyped(x.clone())).get().unwrap(), Some(Value::Int(1)));
    let s = Scope::Thing(t);
    alice.undo(&s).unwrap().unwrap();
    w.run();
    assert!(!bob.has_content(t).unwrap() && bob.groups_of(t).unwrap().within.is_empty());
    alice.redo(&s).unwrap().unwrap();
    w.run();
    assert!(bob.has_content(t).unwrap() && bob.at(t, osis::DynamicAspectKey::untyped(x.clone())).get().unwrap() == Some(Value::Int(1)) && bob.groups_of(t).unwrap().item_of == vec![g]);
    let c = alice.created(t).unwrap().unwrap().id;
    bob.revert(c).unwrap();
    w.run();
    assert!(!alice.has_content(t).unwrap() && alice.groups_of(t).unwrap().within.is_empty());
    let t3 = mk(alice.me());
    w.run();
    assert_eq!(bob.role_on(t3).unwrap(), None);
    let c3 = alice.created(t3).unwrap().unwrap().id;
    assert!(matches!(bob.revert(c3), Err(Error::Permission { .. })));
    w.run();
    assert!(alice.has_content(t3).unwrap() && alice.groups_of(t3).unwrap().item_of == vec![g]);
}

// notes/api.md Commits: a revert of a creation is related to it in a scope naming only
// `created.0`, though it writes none of the aspects the creation wrote (removed meanwhile; seen
// on the other node, which has no log entry of it).
#[test]
fn creation_revert_found_by_created_scope_api_commits() {
    let (da, db) = two_nodes();
    let t = da.commit_with(|w| w.create_with_content(da.me())).unwrap();
    let c = da.created(t).unwrap().unwrap().id;
    commit_with(&da, |w| {
        w.at(t, osis::DynamicAspectKey::untyped(ak("t:made.0"))).remove()?;
        w.at(t, osis::DynamicAspectKey::untyped(ak("t:y.0"))).set(&Value::Int(1))
    });
    let r = da.revert(c).unwrap();
    sync2(&da, &db);
    assert!(!db.has_content(t).unwrap());
    let e = db.commits(&CommitQuery { scope: Some(Scope::Aspects(vec![(t, ak("created.0"))])), ..Default::default() }).unwrap();
    assert_eq!(e.iter().map(|e| (e.commit.id, e.in_effect, e.reverted_by.clone())).collect::<Vec<_>>(), vec![(c, false, vec![r.id])]);
}

// spec/crdt.md §2.2 (commits order by hybrid time, then ID); notes/api.md Commits, History: commits of one millisecond keep their order: a moment's filter takes them all, and paging by `after` or by an entry's place loses none
#[test]
fn one_moment_many_commits_lose_none_api_commits() {
    let c = clock();
    let db = osis::internals::create(cfg(1, MemStore::new(), &c)).unwrap();
    let k = osis::DynamicAspectKey::untyped(ak("t:x.0"));
    let t = db.commit_with(|w| w.create()).unwrap();
    let made: Vec<_> = (0..5).map(|i| commit_with(&db, |w| w.at(t, k.clone()).set(&Value::Int(i)))).collect();
    let at = made[0].written;
    assert!(made.iter().all(|m| m.written == at), "the clock did not move");
    assert_eq!(made.windows(2).filter(|w| w[0].pos() < w[1].pos()).count(), 4, "in the order written");
    let newest_first: Vec<_> = made.iter().rev().map(|m| m.id).collect();
    let base = || CommitQuery { scope: Some(Scope::Aspects(vec![(t, ak("t:x.0"))])), ..Default::default() };
    let ids = |q: CommitQuery| db.commits(&q).unwrap().into_iter().map(|e| e.commit.id).collect::<Vec<_>>();
    assert_eq!(ids(base()), newest_first);
    assert_eq!(ids(CommitQuery { since: Some(at), until: Some(osis::Time(at.0 + 1)), ..base() }), newest_first, "the moment holds them all");
    assert_eq!(ids(CommitQuery { until: Some(at), ..base() }), vec![], "all before none of them");
    // one by one, by `after`
    let (mut seen, mut after) = (Vec::new(), None);
    while let Some(e) = ids(CommitQuery { after, limit: Some(1), ..base() }).pop() {
        seen.push(e);
        after = Some(e);
    }
    assert_eq!(seen, newest_first);
    // and by a history page's places, both ways
    let (mut seen, mut from) = (Vec::new(), osis::HistoryFrom::Newest);
    while let Some(e) = db.at(t, k.clone()).history(from, 1).unwrap().entries.pop() {
        seen.push(e.commit.id);
        from = osis::HistoryFrom::Before(e.pos());
    }
    assert_eq!(seen, newest_first);
    let (mut seen, mut from) = (Vec::new(), osis::HistoryFrom::After(osis::HistoryPos::time(at)));
    while let Some(e) = db.at(t, k.clone()).history(from, 1).unwrap().entries.pop() {
        seen.push(e.commit.id);
        from = osis::HistoryFrom::After(e.pos());
    }
    assert_eq!(seen, made.iter().map(|m| m.id).collect::<Vec<_>>());
}
