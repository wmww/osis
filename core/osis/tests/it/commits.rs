//! The commit query, undo, redo, revert (notes/api.md Commits; spec/commits.md §7, spec/crdt.md §4.6).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common::TestWrites as _;
use osis::internals::Internals as _;
use crate::common;
use common::*;
use crate::common::CreateIn;
use osis::{ChangeId, CommitKind, CommitQuery, DropReason, Error, MemStore, Next, Osis, Scope, Value};
use osis_sim::world::World;

// spec/commits.md §7, notes/api.md Commits: undo and redo walk this actor's own changes in
// scope; redo is an undo of the undo; a new undo after a redo undoes the redone change. A
// register edited twice undoes twice (spec/crdt.md §4.6: the second undo steps back through
// the first undo's restoring write), then redoes twice.
#[test]
fn undo_redo_cycle_spec_commits_7() {
    let db = db(1);
    let k = ak("t:x.0");
    let mut w = db.write();
    let t = w.create().unwrap();
    w.commit().unwrap();
    db.commit_set(t, k.clone(), &Value::Int(1)).unwrap();
    db.commit_set(t, k.clone(), &Value::Int(2)).unwrap();
    let scope = Scope::Aspects(vec![(t, k.clone())]);
    let get = || db.at(t, k.clone()).get().unwrap();
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
    db.commit_set(t, a.clone(), &Value::Int(1)).unwrap();
    db.commit_set(t, b.clone(), &Value::Int(1)).unwrap();
    db.undo(&scope).unwrap().unwrap();
    db.undo(&scope).unwrap().unwrap();
    assert_eq!((db.at(t, a.clone()).get().unwrap(), db.at(t, b.clone()).get().unwrap()), (None, None));
    // another scope sees nothing to undo
    let other = Scope::Aspects(vec![(t, ak("t:other.0"))]);
    assert_eq!(db.undo(&other).unwrap(), None);
}

// notes/api.md Commits (decided): a new change clears the redo stack.
#[test]
fn new_change_clears_redo_spec_commits_7() {
    let db = db(1);
    let (a, b) = (ak("t:a.0"), ak("t:b.0"));
    let mut w = db.write();
    let t = w.create().unwrap();
    w.commit().unwrap();
    db.commit_set(t, a.clone(), &Value::Int(1)).unwrap();
    let scope = Scope::Thing(t);
    db.undo(&scope).unwrap().unwrap();
    db.commit_set(t, b.clone(), &Value::Int(1)).unwrap();
    assert_eq!(db.redo(&scope).unwrap(), None);
    assert_eq!(db.at(t, a).get().unwrap(), None);
    // undo then redo still pairs up after the new change
    db.undo(&scope).unwrap().unwrap();
    assert_eq!(db.at(t, b.clone()).get().unwrap(), None);
    db.redo(&scope).unwrap().unwrap();
    assert_eq!(db.at(t, b).get().unwrap(), Some(Value::Int(1)));
}

// spec/commits.md §7: when the newest change's body was dropped, undo reports it and never
// undoes an older change instead.
#[test]
fn undo_blocked_by_dropped_body_spec_commits_7() {
    let db = db(1);
    let (a, b) = (ak("t:a.0"), ak("t:b.0"));
    let mut w = db.write();
    let t = w.create().unwrap();
    w.commit().unwrap();
    db.commit_set(t, a.clone(), &Value::Int(1)).unwrap();
    let newest = commit_with(&db, |w| w.at(t, b.clone()).set(&Value::Int(1))).id.commit().unwrap();
    db.engine(|e| e.drop_body(&newest, &t, &b)).unwrap();
    assert_eq!(db.undo(&Scope::Thing(t)), Err(Error::NotUndoable { commit: osis::ChangeId::Commit(newest), reason: DropReason::Compacted }));
    assert_eq!(db.at(t, a).get().unwrap(), Some(Value::Int(1)));
    assert_eq!(db.revert(osis::ChangeId::Commit(newest)), Err(Error::NotUndoable { commit: osis::ChangeId::Commit(newest), reason: DropReason::Compacted }));
}

// notes/node.md: an undo mutation carries nothing else.
#[test]
fn undo_mutation_alone_spec_commits_7() {
    let db = db(1);
    let mut w = db.write();
    let t = w.create_durable(db.me()).unwrap();
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
    let c1 = commit_with(&db, |w| w.at(t, k.clone()).set(&Value::Int(1)));
    let mut w = db.write();
    w.act_as(db.node());
    w.at(t, j.clone()).set(&Value::Int(5)).unwrap();
    let c2 = w.commit().unwrap().unwrap();
    // the node's commit is not me's to undo, but revert reverts it
    let u = db.revert(c2.id).unwrap();
    assert_eq!(db.at(t, j.clone()).get().unwrap(), None);
    let all = CommitQuery::new().scope(Scope::Group(g));
    let h = db.commits(&all).unwrap();
    let entry = |c: osis::CommitId| h.iter().find(|e| e.commit.id == osis::ChangeId::Commit(c)).unwrap().clone();
    assert!(!entry(c2.id.commit().unwrap()).in_effect);
    assert_eq!(entry(c2.id.commit().unwrap()).reverted_by, vec![u.id]);
    assert!(entry(u.id.commit().unwrap()).in_effect && entry(c1.id.commit().unwrap()).in_effect);
    assert_eq!((entry(u.id.commit().unwrap()).kind, entry(u.id.commit().unwrap()).reverts), (CommitKind::Revert, Some(c2.id)));
    assert_eq!(entry(c1.id.commit().unwrap()).kind, CommitKind::Change);
    assert_eq!(h.first().map(|e| e.commit.id), Some(u.id));
    let paged = db.commits(&all.clone().after(u.id.commit().unwrap()).limit(1)).unwrap();
    assert_eq!(paged.len(), 1);
    assert_eq!(paged[0].commit.id, h[1].commit.id);
    // purge drops c1's body
    let mut w = db.write();
    w.at(t, k.clone()).purge(osis::Purge::All).unwrap();
    w.commit().unwrap();
    let h = db.commits(&CommitQuery::new().scope(Scope::Aspects(vec![(t, k.clone())]))).unwrap();
    assert!(h.iter().find(|e| e.commit.id == c1.id).unwrap().dropped);
    assert!(db.revert(osis::ChangeId::Commit(osis::CommitId([7; 32]))).is_err());
}

// notes/api.md Commits: each filter of the query, alone; results newest first.
#[test]
fn query_filters_api_commits() {
    let db = db(1);
    let (k, j) = (ak("t:x.0"), ak("t:y.0"));
    let t = db.batch(|w| w.create()).unwrap();
    let c1 = commit_with(&db, |w| w.at(t, k.clone()).set(&Value::Int(1)));
    let mut w = db.write();
    w.act_as(db.node());
    w.at(t, j.clone()).set(&Value::Int(5)).unwrap();
    let c2 = w.commit().unwrap().unwrap();
    let c3 = commit_with(&db, |w| w.at(t, k.clone()).set(&Value::Int(2)));
    let u3 = db.undo(&Scope::Thing(t)).unwrap().unwrap();
    let ids = |q: CommitQuery| db.commits(&q).unwrap().into_iter().map(|e| e.commit.id.commit().unwrap()).collect::<Vec<_>>();
    let base = || CommitQuery::new().scope(Scope::Thing(t));
    let everything = ids(base());
    assert_eq!(everything[..4], [u3.id.commit().unwrap(), c3.id.commit().unwrap(), c2.id.commit().unwrap(), c1.id.commit().unwrap()]);
    assert!(ids(CommitQuery::new()).starts_with(&everything[..4]), "no scope: every held commit");
    assert_eq!(ids(base().scope(Scope::Aspects(vec![(t, j.clone())]))), vec![c2.id.commit().unwrap()]);
    assert_eq!(ids(base().actor(db.node())), vec![c2.id.commit().unwrap()]);
    assert!(!ids(base().actor(db.me())).contains(&c2.id.commit().unwrap()));
    assert_eq!(ids(base().kind(CommitKind::Revert)), vec![u3.id.commit().unwrap()]);
    assert_eq!(ids(base().kind(CommitKind::Change).limit(2)), vec![c3.id.commit().unwrap(), c2.id.commit().unwrap()]);
    assert_eq!(ids(base().reverts(c3.id.commit().unwrap())), vec![u3.id.commit().unwrap()]);
    assert_eq!(ids(base().reverted_by(u3.id.commit().unwrap())), vec![c3.id.commit().unwrap()]);
    assert_eq!(ids(base().in_effect(false)), vec![c3.id.commit().unwrap()]);
    assert_eq!(ids(base().since(c2.ts).until(c3.ts)), vec![c2.id.commit().unwrap()]);
    assert_eq!(ids(base().after(c3.id.commit().unwrap()).kind(CommitKind::Change).limit(1)), vec![c2.id.commit().unwrap()]);
    assert!(db.commits(&base().after(osis::CommitId([7; 32]))).is_err());
    let e = &db.commits(&base().limit(1)).unwrap()[0];
    assert_eq!((e.commit.actor, e.commit.node, e.commit.ts), (db.me(), db.node(), u3.ts));
    assert_eq!(e.aspects, vec![(t, k.clone())]);
}

/// Two devices of one person, paired locally; commits travel by `deliver`.
fn two_devices() -> (Osis, Osis) {
    let c = clock();
    let a = Osis::create(cfg(1, MemStore::new(), &c)).unwrap().0;
    let j = Osis::pair(cfg(2, MemStore::new(), &c), &a.pair_offer().unwrap()).unwrap();
    let (_, reply) = a.pair_accept(j.request()).unwrap();
    let b = j.finish(&reply).unwrap();
    (a, b)
}

fn sync2(a: &Osis, b: &Osis) {
    deliver(a, b);
    deliver(b, a);
}

// notes/api.md Commits: undo and redo act on the actor's commits, whichever device made them:
// device B undoes A's change, A redoes B's undo, B undoes the redo; a revert made on one device
// is found by the other with the same query; a new change on one device clears redo on both.
#[test]
fn undo_redo_across_devices_spec_commits_7() {
    let (da, db) = two_devices();
    let k = ak("t:x.0");
    let t = da.batch(|w| w.create()).unwrap();
    let c1 = commit_with(&da, |w| w.at(t, k.clone()).set(&Value::Int(1)));
    sync2(&da, &db);
    let get = |d: &Osis| d.at(t, k.clone()).get().unwrap();
    assert_eq!(get(&db), Some(Value::Int(1)));
    let scope = Scope::Thing(t);
    let u = db.undo(&scope).unwrap().unwrap();
    assert_eq!(get(&db), None);
    sync2(&da, &db);
    assert_eq!(get(&da), None);
    let found = da.commits(&CommitQuery::new().reverts(c1.id.commit().unwrap())).unwrap();
    assert_eq!(found.iter().map(|e| (e.commit.id, e.commit.node)).collect::<Vec<_>>(), vec![(u.id, db.node())]);
    let r = da.redo(&scope).unwrap().unwrap();
    assert_eq!(get(&da), Some(Value::Int(1)));
    sync2(&da, &db);
    assert_eq!(get(&db), Some(Value::Int(1)));
    assert_eq!(db.commits(&CommitQuery::new().reverts(u.id.commit().unwrap())).unwrap()[0].commit.id, r.id);
    assert_eq!(db.redo(&scope).unwrap(), None, "no undo in effect");
    db.undo(&scope).unwrap().unwrap();
    assert_eq!(get(&db), None);
    sync2(&da, &db);
    assert_eq!(get(&da), None);
    // a new change on A clears redo on B too
    commit_with(&da, |w| w.at(t, ak("t:y.0")).set(&Value::Int(3)));
    sync2(&da, &db);
    assert_eq!(db.redo(&scope).unwrap(), None);
    assert_eq!(get(&db), None);
}

// notes/api.md Commits: another actor's revert of my change is found with the same query; my
// undo skips the change it reverted; for its author the revert is an undo: redo reverts it.
#[test]
fn find_another_actors_revert_api_commits() {
    let mut w = World::new();
    let host = w.add_host();
    let alice = crate::scenario::person(&mut w, 1, host);
    let bob = crate::scenario::person(&mut w, 2, host);
    let b = crate::scenario::introduce(&mut w, &alice, &bob);
    let k = ak("t:x.0");
    let t = alice
        .batch(|wr| {
            let t = wr.create()?;
            Ok(t)
        })
        .unwrap();
    alice.sync(t, &[]).unwrap();
    alice.grant(t, b, osis::Role::Write, osis::GrantOpts::default()).unwrap();
    w.run();
    let c = commit_with(&alice, |wr| wr.at(t, k.clone()).set(&Value::Int(1)));
    w.run();
    assert_eq!(bob.at(t, k.clone()).get().unwrap(), Some(Value::Int(1)));
    let r = bob.revert(c.id).unwrap();
    w.run();
    assert_eq!(alice.at(t, k.clone()).get().unwrap(), None);
    let found = alice.commits(&CommitQuery::new().reverts(c.id.commit().unwrap())).unwrap();
    assert_eq!(found.iter().map(|e| (e.commit.id, e.commit.actor)).collect::<Vec<_>>(), vec![(r.id, bob.me())]);
    let mine = alice.commits(&CommitQuery::new().scope(Scope::Thing(t)).actor(alice.me()).kind(CommitKind::Change)).unwrap();
    assert!(mine.iter().any(|e| e.commit.id == c.id && !e.in_effect && e.reverted_by == vec![r.id]));
    assert_eq!(alice.undo(&Scope::Aspects(vec![(t, k.clone())])).unwrap(), None, "alice's change is out of effect");
    // bob's revert is a revert: his undo skips it, his redo reverts it
    assert_eq!(bob.undo(&Scope::Thing(t)).unwrap(), None, "bob made no change");
    bob.redo(&Scope::Thing(t)).unwrap().unwrap();
    w.run();
    assert_eq!(alice.at(t, k).get().unwrap(), Some(Value::Int(1)));
}

// spec/crdt.md §4.6: undo never steps back over a live later change: x = 1, 2, 1, 5; undoing
// the 5 restores 1, and a selective undo of the first write is then superseded (the later
// writes are still in effect), so x stays 1.
#[test]
fn undo_chain_stops_at_a_live_change_spec_crdt_4_6() {
    let db = db(1);
    let k = ak("t:x.0");
    let mut w = db.write();
    let t = w.create_durable(db.me()).unwrap();
    w.commit().unwrap();
    let c1 = commit_with(&db, |w| w.at(t, k.clone()).set(&Value::Int(1)));
    commit_with(&db, |w| w.at(t, k.clone()).set(&Value::Int(2)));
    commit_with(&db, |w| w.at(t, k.clone()).set(&Value::Int(1)));
    commit_with(&db, |w| w.at(t, k.clone()).set(&Value::Int(5)));
    db.undo(&Scope::Thing(t)).unwrap().unwrap();
    assert_eq!(db.at(t, k.clone()).get().unwrap(), Some(Value::Int(1)));
    assert_eq!(db.revert(c1.id), Err(Error::NotUndoable { commit: c1.id, reason: DropReason::Superseded }));
    assert_eq!(db.at(t, k).get().unwrap(), Some(Value::Int(1)));
}

// spec/crdt.md §4.6: "in effect" is a property of the whole commit. Z writes x = 5 and z, X
// writes x = 1 and y; their undos write only z and y (on x, neither write was the winner any
// more). Undoing Y (x = 3) restores x = 1; a revert of W (the first x = 1) then steps back
// through that restoring write: Z and X are out of effect (undone by commits that never wrote
// x), so no live change stands after W.
#[test]
fn in_effect_is_whole_commit_spec_crdt_4_6() {
    let db = db(1);
    let (x, y, z) = (ak("t:x.0"), ak("t:y.0"), ak("t:z.0"));
    let t = db.batch(|w| w.create_durable(db.me())).unwrap();
    commit_with(&db, |w| w.at(t, x.clone()).set(&Value::Int(0)));
    let cw = commit_with(&db, |w| w.at(t, x.clone()).set(&Value::Int(1)));
    let cz = commit_with(&db, |w| {
        w.at(t, x.clone()).set(&Value::Int(5))?;
        w.at(t, z.clone()).set(&Value::Int(1))
    });
    let cx = commit_with(&db, |w| {
        w.at(t, x.clone()).set(&Value::Int(1))?;
        w.at(t, y.clone()).set(&Value::Int(2))
    });
    let cy = commit_with(&db, |w| w.at(t, x.clone()).set(&Value::Int(3)));
    for c in [cx.id, cz.id] {
        let u = db.revert(c).unwrap();
        assert!(db.commits(&CommitQuery::new().scope(Scope::Aspects(vec![(t, x.clone())]))).unwrap().iter().all(|e| e.commit.id != u.id), "the undo writes nothing on x");
    }
    assert_eq!((db.at(t, y.clone()).get().unwrap(), db.at(t, z).get().unwrap()), (None, None));
    db.revert(cy.id).unwrap();
    assert_eq!(db.at(t, x.clone()).get().unwrap(), Some(Value::Int(1)));
    db.revert(cw.id).unwrap();
    assert_eq!(db.at(t, x).get().unwrap(), Some(Value::Int(0)));
}

// notes/api.md Attribution, spec/permissions.md §5.2: the API reports only verifiable authorship.
// B holds A's signed change: history lists it with A's node and `ts`. C holds only A's snapshot
// of the aspect: the value reads the same, its watch reports the change as the snapshot's (its
// author, ID and `ts`), and its history claims nothing for the change it never held.
#[test]
fn snapshot_only_attribution_api_history() {
    use osis::Source;
    let (a, b, c) = (db(1), db(2), db(3));
    let k = ak("t:x.0");
    let t = a.batch(|w| w.create_durable(a.me())).unwrap();
    deliver(&a, &b);
    deliver(&a, &c);
    let done = commit_with(&a, |w| w.at(t, k.clone()).set(&Value::Int(7)));
    let snap = a.engine(|e| e.snapshot(&t, &k)).unwrap().unwrap();
    let snap_ts = a.engine(|e| e.header(&snap)).unwrap().ts;
    assert!(snap_ts > done.ts);
    deliver(&a, &b);
    let (tx, rx) = std::sync::mpsc::channel();
    let _s = c.at(t, k.clone()).on_change(move |_, ch| tx.send(ch).unwrap()).unwrap();
    assert_eq!(recv(&rx).source, Source::Initial);
    let pks = a.engine(|e| e.commit_ids().iter().filter(|id| **id != done.id.commit().unwrap()).filter_map(|id| e.package(id).unwrap()).collect::<Vec<_>>());
    for pk in pks {
        c.engine(|e| e.ingest(&pk.bytes, pk.blobs.clone()).unwrap());
    }
    let ch = recv(&rx);
    assert_eq!(ch.value, Ok(Some(Value::Int(7))));
    assert!(matches!(ch.source, Source::Remote(i) if i.id == osis::ChangeId::Commit(snap) && i.node == a.node() && i.ts == snap_ts), "{:?}", ch.source);
    let q = CommitQuery::new().scope(Scope::Thing(t));
    let hb = b.commits(&q).unwrap();
    assert!(hb.iter().any(|e| e.commit.id == done.id && e.commit.node == a.node() && e.commit.ts == done.ts), "{hb:?}");
    let hc = c.commits(&q).unwrap();
    assert!(hc.iter().all(|e| e.commit.id != done.id && e.commit.ts != done.ts), "{hc:?}");
    assert!(hc.iter().any(|e| e.commit.id == osis::ChangeId::Commit(snap) && e.kind == CommitKind::Snapshot), "the snapshot as itself: {hc:?}");
}

const DOC_SCHEMA: &str = "version 1;\naspect x:doc.0: struct { 0 name: string, 1 tags: set<string>, 2 extra: enum { 0 none, 1 some(struct { 0 notes: set<string> }) }, 3 items: list<string> };\n";

fn field(id: u64) -> osis::Step {
    osis::Step::Field(id)
}

// spec/crdt.md §4.6 "Absent before" (exact undo): undoing the first write into a spot that did
// not exist (a struct field's set, a set in an enum payload, a list) makes it absent again, so
// the read equals the read before; a concurrent write into it arriving after the undo is wiped,
// one already held when undoing is not.
#[test]
fn exact_undo_spec_crdt_4_6() {
    let (a, b) = two_devices();
    for d in [&a, &b] {
        d.register_schema("doc.osis", DOC_SCHEMA).unwrap();
    }
    let doc = ak("x:doc.0");
    let t = a.batch(|w| w.create()).unwrap();
    a.batch(|w| {
        w.at(t, doc.clone()).path(osis::Path(vec![field(0)])).set(&"n".to_string())?;
        w.at(t, doc.clone()).path(osis::Path(vec![field(2)])).set(&Value::Enum(1, Some(Box::new(Value::Map(Default::default())))))
    })
    .unwrap();
    sync2(&a, &b);
    let before = a.at(t, doc.clone()).get().unwrap();
    let scope = Scope::Thing(t);
    let spots: [(&str, osis::Path); 3] = [
        ("struct field set", osis::Path(vec![field(1)])),
        ("enum payload set", osis::Path(vec![field(2), osis::Step::Case(1), field(0)])),
        ("list", osis::Path(vec![field(3)])),
    ];
    let write = |d: &Osis, p: &osis::Path, item: &str| {
        let item = item.to_string();
        let key = d.key("x:doc.0").unwrap();
        d.batch(|w| if p.0.len() == 1 && p.0[0] == field(3) { w.at(t, key.clone()).path(p.clone()).splice(0..0, &[item]) } else { w.at(t, key.clone()).path(p.clone()).add(&item) }).unwrap();
    };
    for (name, p) in &spots {
        write(&a, p, "x");
        assert_ne!(a.at(t, doc.clone()).get().unwrap(), before, "{name}");
        a.undo(&scope).unwrap().unwrap();
        assert_eq!(a.at(t, doc.clone()).get().unwrap(), before, "{name}");
        // concurrent: b writes into the spot unseen, a writes and undoes, then they meet
        write(&b, p, "y");
        let b_only = b.at(t, doc.clone()).get().unwrap();
        write(&a, p, "x");
        a.undo(&scope).unwrap().unwrap();
        sync2(&a, &b);
        assert_eq!(a.at(t, doc.clone()).get().unwrap(), before, "{name}: b's concurrent write wiped");
        assert_eq!(b.at(t, doc.clone()).get().unwrap(), before, "{name}");
        // seen: b's write is held when a undoes, so only a's write goes
        write(&b, p, "y");
        sync2(&a, &b);
        write(&a, p, "x");

        a.undo(&scope).unwrap().unwrap();
        assert_eq!(a.at(t, doc.clone()).get().unwrap(), b_only, "{name}: b's held write stays");
        // back to the start for the next spot: b undoes its write (a's undone write's
        // tombstone carries no value, so it does not block the reset)
        sync2(&a, &b);
        b.undo(&scope).unwrap().unwrap();
        sync2(&a, &b);
        assert_eq!(a.at(t, doc.clone()).get().unwrap(), before, "{name}");
    }
}


/// What `next` picks in `scope`.
fn next(db: &Osis, scope: &Scope, n: Next) -> Option<ChangeId> {
    let v = db.commits(&CommitQuery::new().scope(scope.clone()).next(n)).unwrap();
    assert!(v.len() <= 1);
    v.first().map(|e| e.commit.id)
}

/// Undo (redo) in `scope`, checking it reverts what `next` reported.
fn step(db: &Osis, scope: &Scope, n: Next) -> Option<ChangeId> {
    let want = next(db, scope, n);
    let got = match n {
        Next::Undo => db.undo(scope),
        Next::Redo => db.redo(scope),
    }
    .unwrap()
    .map(|c| c.id);
    match (want, got) {
        (Some(w), Some(g)) => assert_eq!(db.commits(&CommitQuery::new().reverted_by(g)).unwrap().iter().map(|e| e.commit.id).collect::<Vec<_>>(), vec![w], "reverts what next reported"),
        (None, None) => {}
        x => panic!("next and the step disagree: {x:?}"),
    }
    got
}

// spec/crdt.md §4.6 Undoing a creation, notes/api.md Commits: undoing the commit that created a
// thing deletes it, its placements in every group included (one made later in another group,
// and a subgroup edge); redo brings it back with its content and placements. `next` reports the
// change each step then reverts.
#[test]
fn undo_of_creation_deletes_spec_crdt_4_6() {
    let db = db(1);
    let (x, y) = (ak("t:x.0"), ak("t:y.0"));
    // groups already: a first member would write the group durably in the batch
    let mk = |db: &Osis| db.batch(|w| { let g = w.create_durable(db.me())?; let d = w.create_durable(db.me())?; w.group(g).add(osis::Member::Item(d))?; Ok(g) }).unwrap();
    let (f, f2, f3) = (mk(&db), mk(&db), mk(&db));
    let t = db.batch(|w| { let t = w.create_in(db.me(), &[f])?; w.at(t, x.clone()).set(&Value::Int(1))?; Ok(t) }).unwrap();
    let created = db.created(t).unwrap().unwrap().commit.map(ChangeId::Commit).unwrap();
    db.batch(|w| { w.group(f2).add(osis::Member::Item(t))?; w.group(f3).add(osis::Member::Subgroup(t)) }).unwrap();
    let edit = commit_with(&db, |w| w.at(t, y.clone()).set(&Value::Int(2))).id;
    let s = Scope::Thing(t);
    assert_eq!(next(&db, &s, Next::Redo), None);
    assert_eq!(next(&db, &s, Next::Undo), Some(edit));
    step(&db, &s, Next::Undo).unwrap();
    assert_eq!(db.at(t, y.clone()).get().unwrap(), None);
    assert_eq!(next(&db, &s, Next::Undo), Some(created));
    step(&db, &s, Next::Undo).unwrap();
    let gs = db.groups_of(t).unwrap();
    assert!(!db.knows(t).unwrap() && gs.item_of.is_empty() && gs.subgroup_of.is_empty() && db.at(t, x.clone()).get().unwrap().is_none(), "deleted: {gs:?}");
    assert_eq!(next(&db, &s, Next::Undo), None);
    step(&db, &s, Next::Redo).unwrap();
    let gs = db.groups_of(t).unwrap();
    assert!(db.knows(t).unwrap() && db.at(t, x.clone()).get().unwrap() == Some(Value::Int(1)));
    let mut items = gs.item_of;
    items.sort();
    let mut want = vec![f, f2];
    want.sort();
    assert_eq!((items, gs.subgroup_of), (want, vec![f3]));
    step(&db, &s, Next::Redo).unwrap();
    assert_eq!(db.at(t, y.clone()).get().unwrap(), Some(Value::Int(2)));
    assert_eq!(next(&db, &s, Next::Redo), None);
    // reverting the creation directly, with a later change in effect, deletes too (the later
    // content goes with it), and reverting that revert restores everything
    let r = db.revert(created).unwrap();
    assert!(!db.knows(t).unwrap() && db.at(t, y.clone()).get().unwrap().is_none() && db.groups_of(t).unwrap().within.is_empty());
    db.revert(r.id).unwrap();
    assert!(db.at(t, x).get().unwrap() == Some(Value::Int(1)) && db.at(t, y).get().unwrap() == Some(Value::Int(2)) && db.groups_of(t).unwrap().within.len() == 2);
}

// notes/ephemeral.md API delta (Undo), spec/crdt.md §4.6: undoing the batch that created an
// ephemeral thing deletes it (it reads unknown, its ephemeral placements in every group go);
// redo brings it back placed.
#[test]
fn undo_of_ephemeral_creation_deletes_spec_crdt_4_6() {
    let db = db(2);
    let k = ak("app:draft.0~");
    // groups already: a first member would write the group durably in the batch
    let mk = |db: &Osis| db.batch(|w| { let g = w.create_durable(db.me())?; let d = w.create_durable(db.me())?; w.group(g).add(osis::Member::Item(d))?; Ok(g) }).unwrap();
    let (f, f2) = (mk(&db), mk(&db));
    let mut w = db.write();
    let e = w.create_in(db.me(), &[f]).unwrap();
    w.at(e, k.clone()).set(&Value::Int(1)).unwrap();
    w.commit().unwrap();
    let mut w = db.write();
    w.group(f2).add(osis::Member::Item(e)).unwrap();
    w.commit().unwrap();
    let sorted = |mut v: Vec<osis::Tid>| {
        v.sort();
        v
    };
    assert_eq!(sorted(db.groups_of(e).unwrap().item_of), sorted(vec![f, f2]));
    let s = Scope::Thing(e);
    // the placement in f2 is a write of f2: outside the thing's scope, so undo picks the creation
    let picked = next(&db, &s, Next::Undo).unwrap();
    assert!(matches!(picked, ChangeId::Ephemeral(_)));
    step(&db, &s, Next::Undo).unwrap();
    assert!(!db.knows(e).unwrap() && db.groups_of(e).unwrap().item_of.is_empty() && db.at(e, k.clone()).get().unwrap().is_none());
    assert_eq!(step(&db, &s, Next::Undo), None);
    step(&db, &s, Next::Redo).unwrap();
    assert!(db.knows(e).unwrap() && db.at(e, k).get().unwrap() == Some(Value::Int(1)));
    assert_eq!(sorted(db.groups_of(e).unwrap().item_of), sorted(vec![f, f2]));
    // still an ephemeral thing: nothing reached the store for it
    assert_eq!(db.created(e).unwrap().unwrap().commit, None);
}

// notes/api.md Commits: `next` reports what undo and redo would revert, in a thing and in a
// broader scope; a new change clears what redo would revert; `next` needs a scope.
#[test]
fn next_reports_what_undo_and_redo_revert_api_commits() {
    let db = db(3);
    let k = ak("t:x.0");
    let f = db.batch(|w| { let g = w.create_durable(db.me())?; Ok(g) }).unwrap();
    let in_f = |w: &mut osis::Write<'_>| -> osis::Result<osis::Tid> {
        let t = w.create_durable(db.me())?;
        w.group(f).add(osis::Member::Item(t))?;
        Ok(t)
    };
    let (a, b) = db.batch(|w| Ok((in_f(w)?, in_f(w)?))).unwrap();
    let ca = commit_with(&db, |w| w.at(a, k.clone()).set(&Value::Int(1))).id;
    let cb = commit_with(&db, |w| w.at(b, k.clone()).set(&Value::Int(1))).id;
    let (sa, sf) = (Scope::Thing(a), Scope::Group(f));
    assert_eq!((next(&db, &sa, Next::Undo), next(&db, &sf, Next::Undo)), (Some(ca), Some(cb)));
    let u = step(&db, &sa, Next::Undo).unwrap();
    assert_eq!((next(&db, &sa, Next::Redo), next(&db, &sf, Next::Redo)), (Some(u), Some(u)));
    // the group's newest change is still b's, in effect
    assert_eq!(next(&db, &sf, Next::Undo), Some(cb));
    // a new change in the group clears its redo, not the thing's
    let cb2 = commit_with(&db, |w| w.at(b, k.clone()).set(&Value::Int(2))).id;
    assert_eq!((next(&db, &sf, Next::Redo), next(&db, &sa, Next::Redo)), (None, Some(u)));
    assert_eq!(step(&db, &sf, Next::Redo), None);
    assert_eq!(next(&db, &sf, Next::Undo), Some(cb2));
    step(&db, &sa, Next::Redo).unwrap();
    assert_eq!(db.at(a, k).get().unwrap(), Some(Value::Int(1)));
    assert!(matches!(db.commits(&CommitQuery::new().next(Next::Undo)), Err(Error::Invalid(_))));
}

// spec/crdt.md §4.6 Undoing a creation, shared: the undo of a creation reaches the other
// holder (deleted there), redo restores it there; a writer (not admin) may revert another's
// creation of a thing it may write; reverting the creation of a thing it may not write is
// `Permission` and changes nothing (never a partial revert: unplaced but not deleted).
#[test]
fn undo_of_creation_shared_spec_crdt_4_6() {
    let mut w = World::new();
    let host = w.add_host();
    let alice = crate::scenario::person(&mut w, 1, host);
    let bob = crate::scenario::person(&mut w, 2, host);
    let b = crate::scenario::introduce(&mut w, &alice, &bob);
    let x = ak("t:x.0");
    let g = alice.batch(|wr| { let g = wr.create()?; Ok(g) }).unwrap();
    alice.sync(g, &[]).unwrap();
    alice.grant(g, b, osis::Role::Write, osis::GrantOpts::default()).unwrap();
    w.run();
    let mk = |owner: osis::Tid| alice.batch(|wr| { let t = wr.create_in(owner, &[g])?; wr.at(t, x.clone()).set(&Value::Int(1))?; Ok(t) }).unwrap();
    let t = mk(g);
    w.run();
    assert_eq!(bob.at(t, x.clone()).get().unwrap(), Some(Value::Int(1)));
    let s = Scope::Thing(t);
    alice.undo(&s).unwrap().unwrap();
    w.run();
    assert!(!bob.knows(t).unwrap() && bob.groups_of(t).unwrap().within.is_empty());
    alice.redo(&s).unwrap().unwrap();
    w.run();
    assert!(bob.knows(t).unwrap() && bob.at(t, x.clone()).get().unwrap() == Some(Value::Int(1)) && bob.groups_of(t).unwrap().item_of == vec![g]);
    let c = ChangeId::Commit(alice.created(t).unwrap().unwrap().commit.unwrap());
    bob.revert(c).unwrap();
    w.run();
    assert!(!alice.knows(t).unwrap() && alice.groups_of(t).unwrap().within.is_empty());
    let t3 = mk(alice.me());
    w.run();
    assert_eq!(bob.role_on(t3).unwrap(), None);
    let c3 = ChangeId::Commit(alice.created(t3).unwrap().unwrap().commit.unwrap());
    assert!(matches!(bob.revert(c3), Err(Error::Permission { .. })));
    w.run();
    assert!(alice.knows(t3).unwrap() && alice.groups_of(t3).unwrap().item_of == vec![g]);
}

// notes/api.md Commits: a revert of a creation is related to it in a scope naming only
// `created.0`, though it writes none of the aspects the creation wrote (removed meanwhile; seen
// on the other device, which has no log entry of it).
#[test]
fn creation_revert_found_by_created_scope_api_commits() {
    let (da, db) = two_devices();
    let t = da.batch(|w| w.create_durable(da.me())).unwrap();
    let c = da.created(t).unwrap().unwrap().commit.map(ChangeId::Commit).unwrap();
    commit_with(&da, |w| {
        w.at(t, ak("t:made.0")).remove()?;
        w.at(t, ak("t:y.0")).set(&Value::Int(1))
    });
    let r = da.revert(c).unwrap();
    sync2(&da, &db);
    assert!(!db.knows(t).unwrap());
    let e = db.commits(&CommitQuery::new().scope(Scope::Aspects(vec![(t, ak("created.0"))]))).unwrap();
    assert_eq!(e.iter().map(|e| (e.commit.id, e.in_effect, e.reverted_by.clone())).collect::<Vec<_>>(), vec![(c, false, vec![r.id])]);
}
