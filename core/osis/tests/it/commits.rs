//! The commit query, undo, redo, revert (notes/api.md Commits; spec/commits.md §7, spec/crdt.md §4.6).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common;
use common::*;
use osis::{CommitKind, CommitQuery, DropReason, Error, MemStore, Osis, Place, Scope, Value};
use osis_sim::world::World;

// spec/commits.md §7, notes/api.md Commits: undo and redo walk this actor's own changes in
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
    let scope = Scope::Aspects(vec![(t, k.clone())]);
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
    let scope = Scope::Thing(t);
    let (a, b) = (ak("/t/a"), ak("/t/b"));
    db.write_with(|w| w.at(t, a.clone()).set(&Value::Int(1))).unwrap();
    db.write_with(|w| w.at(t, b.clone()).set(&Value::Int(1))).unwrap();
    db.undo(&scope).unwrap().unwrap();
    db.undo(&scope).unwrap().unwrap();
    assert_eq!((db.get(t, a.clone()).unwrap(), db.get(t, b.clone()).unwrap()), (None, None));
    // another scope sees nothing to undo
    let other = Scope::Aspects(vec![(t, ak("/t/other"))]);
    assert_eq!(db.undo(&other).unwrap(), None);
}

// notes/api.md Commits (decided): a new change clears the redo stack.
#[test]
fn new_change_clears_redo_spec_commits_7() {
    let db = db(1);
    let (a, b) = (ak("/t/a"), ak("/t/b"));
    let mut w = db.write();
    let t = w.create(db.me(), Place::Unsynced).unwrap();
    w.commit().unwrap();
    db.write_with(|w| w.at(t, a.clone()).set(&Value::Int(1))).unwrap();
    let scope = Scope::Thing(t);
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
    assert_eq!(db.undo(&Scope::Thing(t)), Err(Error::NotUndoable { commit: newest, reason: DropReason::Compacted }));
    assert_eq!(db.get(t, a).unwrap(), Some(Value::Int(1)));
    assert_eq!(db.revert(newest), Err(Error::NotUndoable { commit: newest, reason: DropReason::Compacted }));
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

// notes/api.md Commits: the query lists everyone's commits in scope with their relations; a
// change whose body was dropped is `dropped`, never a silent no-op; revert reverts any commit
// this node may write.
#[test]
fn query_relations_spec_crdt_4_6() {
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
    // the node's commit is not me's to undo, but revert reverts it
    let u = db.revert(c2.commit).unwrap();
    assert_eq!(db.get(t, j.clone()).unwrap(), None);
    let all = CommitQuery::new().scope(Scope::Group(g));
    let h = db.commits(&all).unwrap();
    let entry = |c: osis::CommitId| h.iter().find(|e| e.commit.id == c).unwrap().clone();
    assert!(!entry(c2.commit).in_effect);
    assert_eq!(entry(c2.commit).reverted_by, vec![u.commit]);
    assert!(entry(u.commit).in_effect && entry(c1.commit).in_effect);
    assert_eq!((entry(u.commit).kind, entry(u.commit).reverts), (CommitKind::Revert, Some(c2.commit)));
    assert_eq!(entry(c1.commit).kind, CommitKind::Change);
    assert_eq!(h.first().map(|e| e.commit.id), Some(u.commit));
    let paged = db.commits(&all.clone().after(u.commit).limit(1)).unwrap();
    assert_eq!(paged.len(), 1);
    assert_eq!(paged[0].commit.id, h[1].commit.id);
    // purge drops c1's body
    db.write_with(|w| w.at(t, k.clone()).purge()).unwrap();
    let h = db.commits(&CommitQuery::new().scope(Scope::Aspects(vec![(t, k.clone())]))).unwrap();
    assert!(h.iter().find(|e| e.commit.id == c1.commit).unwrap().dropped);
    assert!(db.revert(osis::CommitId([7; 32])).is_err());
}

// notes/api.md Commits: each filter of the query, alone; results newest first.
#[test]
fn query_filters_api_commits() {
    let db = db(1);
    let (k, j) = (ak("/t/x"), ak("/t/y"));
    let t = db.write_with(|w| w.create(db.me(), Place::Unsynced)).unwrap();
    let c1 = commit_with(&db, |w| w.at(t, k.clone()).set(&Value::Int(1)));
    let mut w = db.write();
    w.act_as(db.node());
    w.at(t, j.clone()).set(&Value::Int(5)).unwrap();
    let c2 = w.commit().unwrap().unwrap();
    let c3 = commit_with(&db, |w| w.at(t, k.clone()).set(&Value::Int(2)));
    let u3 = db.undo(&Scope::Thing(t)).unwrap().unwrap();
    let ids = |q: CommitQuery| db.commits(&q).unwrap().into_iter().map(|e| e.commit.id).collect::<Vec<_>>();
    let base = || CommitQuery::new().scope(Scope::Thing(t));
    let everything = ids(base());
    assert_eq!(everything[..4], [u3.commit, c3.commit, c2.commit, c1.commit]);
    assert!(ids(CommitQuery::new()).starts_with(&everything[..4]), "no scope: every held commit");
    assert_eq!(ids(base().scope(Scope::Aspects(vec![(t, j.clone())]))), vec![c2.commit]);
    assert_eq!(ids(base().actor(db.node())), vec![c2.commit]);
    assert!(!ids(base().actor(db.me())).contains(&c2.commit));
    assert_eq!(ids(base().kind(CommitKind::Revert)), vec![u3.commit]);
    assert_eq!(ids(base().kind(CommitKind::Change).limit(2)), vec![c3.commit, c2.commit]);
    assert_eq!(ids(base().reverts(c3.commit)), vec![u3.commit]);
    assert_eq!(ids(base().reverted_by(u3.commit)), vec![c3.commit]);
    assert_eq!(ids(base().in_effect(false)), vec![c3.commit]);
    assert_eq!(ids(base().since(c2.ts).until(c3.ts)), vec![c2.commit]);
    assert_eq!(ids(base().after(c3.commit).kind(CommitKind::Change).limit(1)), vec![c2.commit]);
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
    let k = ak("/t/x");
    let t = da.write_with(|w| w.create(da.me(), Place::Unsynced)).unwrap();
    let c1 = commit_with(&da, |w| w.at(t, k.clone()).set(&Value::Int(1)));
    sync2(&da, &db);
    let get = |d: &Osis| d.get(t, k.clone()).unwrap();
    assert_eq!(get(&db), Some(Value::Int(1)));
    let scope = Scope::Thing(t);
    let u = db.undo(&scope).unwrap().unwrap();
    assert_eq!(get(&db), None);
    sync2(&da, &db);
    assert_eq!(get(&da), None);
    let found = da.commits(&CommitQuery::new().reverts(c1.commit)).unwrap();
    assert_eq!(found.iter().map(|e| (e.commit.id, e.commit.node)).collect::<Vec<_>>(), vec![(u.commit, db.node())]);
    let r = da.redo(&scope).unwrap().unwrap();
    assert_eq!(get(&da), Some(Value::Int(1)));
    sync2(&da, &db);
    assert_eq!(get(&db), Some(Value::Int(1)));
    assert_eq!(db.commits(&CommitQuery::new().reverts(u.commit)).unwrap()[0].commit.id, r.commit);
    assert_eq!(db.redo(&scope).unwrap(), None, "no undo in effect");
    db.undo(&scope).unwrap().unwrap();
    assert_eq!(get(&db), None);
    sync2(&da, &db);
    assert_eq!(get(&da), None);
    // a new change on A clears redo on B too
    commit_with(&da, |w| w.at(t, ak("/t/y")).set(&Value::Int(3)));
    sync2(&da, &db);
    assert_eq!(db.redo(&scope).unwrap(), None);
    assert_eq!(get(&db), None);
}

// notes/api.md Commits: another actor's revert of my change is found with the same query; my
// undo skips the change it reverted; for its author the revert is an undo: redo reverts it.
#[test]
fn find_another_actors_revert_api_commits() {
    let mut w = World::new();
    let sv = w.add_server().unwrap();
    let alice = crate::scenario::person(&mut w, 1, sv);
    let bob = crate::scenario::person(&mut w, 2, sv);
    let b = crate::scenario::introduce(&mut w, &alice, &bob);
    let k = ak("/t/x");
    let t = alice
        .write_with(|wr| {
            let t = wr.create(alice.me(), Place::Unsynced)?;
            wr.make_group(t)?;
            Ok(t)
        })
        .unwrap();
    alice.sync(t, &[]).unwrap();
    alice.grant(t, b, osis::Role::Write, osis::EdgeOpts::default()).unwrap();
    w.run();
    let c = commit_with(&alice, |wr| wr.at(t, k.clone()).set(&Value::Int(1)));
    w.run();
    assert_eq!(bob.get(t, k.clone()).unwrap(), Some(Value::Int(1)));
    let r = bob.revert(c.commit).unwrap();
    w.run();
    assert_eq!(alice.get(t, k.clone()).unwrap(), None);
    let found = alice.commits(&CommitQuery::new().reverts(c.commit)).unwrap();
    assert_eq!(found.iter().map(|e| (e.commit.id, e.commit.actor)).collect::<Vec<_>>(), vec![(r.commit, bob.me())]);
    let mine = alice.commits(&CommitQuery::new().scope(Scope::Thing(t)).actor(alice.me()).kind(CommitKind::Change)).unwrap();
    assert!(mine.iter().any(|e| e.commit.id == c.commit && !e.in_effect && e.reverted_by == vec![r.commit]));
    assert_eq!(alice.undo(&Scope::Aspects(vec![(t, k.clone())])).unwrap(), None, "alice's change is out of effect");
    // bob's revert is a revert: his undo skips it, his redo reverts it
    assert_eq!(bob.undo(&Scope::Thing(t)).unwrap(), None, "bob made no change");
    bob.redo(&Scope::Thing(t)).unwrap().unwrap();
    w.run();
    assert_eq!(alice.get(t, k).unwrap(), Some(Value::Int(1)));
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
    db.undo(&Scope::Thing(t)).unwrap().unwrap();
    assert_eq!(db.get(t, k.clone()).unwrap(), Some(Value::Int(1)));
    assert_eq!(db.revert(c1.commit), Err(Error::NotUndoable { commit: c1.commit, reason: DropReason::Superseded }));
    assert_eq!(db.get(t, k).unwrap(), Some(Value::Int(1)));
}

// notes/api.md Attribution, spec/permissions.md §5.2: the API reports only verifiable authorship.
// B holds A's signed change: history lists it with A's node and `ts`. C holds only A's snapshot
// of the aspect: the value reads the same, its watch reports the change as the snapshot's (its
// author, ID and `ts`), and its history claims nothing for the change it never held.
#[test]
fn snapshot_only_attribution_api_history() {
    use osis::Source;
    let (a, b, c) = (db(1), db(2), db(3));
    let k = ak("/t/x");
    let t = a.write_with(|w| w.create(a.me(), Place::Unsynced)).unwrap();
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
    let pks = a.engine(|e| e.commit_ids().iter().filter(|id| **id != done.commit).filter_map(|id| e.package(id).unwrap()).collect::<Vec<_>>());
    for pk in pks {
        c.engine(|e| e.ingest(&pk.bytes, pk.blobs.clone()).unwrap());
    }
    let ch = recv(&rx);
    assert_eq!(ch.value, Ok(Some(Value::Int(7))));
    assert!(matches!(ch.source, Source::Remote(i) if i.id == snap && i.node == a.node() && i.ts == snap_ts), "{:?}", ch.source);
    let q = CommitQuery::new().scope(Scope::Thing(t));
    let hb = b.commits(&q).unwrap();
    assert!(hb.iter().any(|e| e.commit.id == done.commit && e.commit.node == a.node() && e.commit.ts == done.ts), "{hb:?}");
    let hc = c.commits(&q).unwrap();
    assert!(hc.iter().all(|e| e.commit.id != done.commit && e.commit.ts != done.ts), "{hc:?}");
    assert!(hc.iter().any(|e| e.commit.id == snap && e.kind == CommitKind::Snapshot), "the snapshot as itself: {hc:?}");
}

const DOC_SCHEMA: &str = "schema 0x0123456789abcdef0123456789abcd02;\nrevision 1;\naspect /x/doc: struct { 0 name: string, 1 tags: set<string>, 2 extra: enum { 0 none, 1 some(struct { 0 notes: set<string> }) }, 3 items: list<string> };\n";

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
        d.register_schema_source("doc.osis", DOC_SCHEMA).unwrap();
    }
    let doc = ak("/x/doc");
    let t = a.write_with(|w| w.create(a.me(), Place::Unsynced)).unwrap();
    a.write_with(|w| {
        w.at(t, doc.clone()).path(osis::Path(vec![field(0)])).set(&"n".to_string())?;
        w.at(t, doc.clone()).path(osis::Path(vec![field(2)])).set_case(osis::CaseId(1), Some(Value::Map(Default::default())))
    })
    .unwrap();
    sync2(&a, &b);
    let before = a.get(t, doc.clone()).unwrap();
    let scope = Scope::Thing(t);
    let spots: [(&str, osis::Path); 3] = [
        ("struct field set", osis::Path(vec![field(1)])),
        ("enum payload set", osis::Path(vec![field(2), osis::Step::Case(1), field(0)])),
        ("list", osis::Path(vec![field(3)])),
    ];
    let write = |d: &Osis, p: &osis::Path, item: &str| {
        let item = item.to_string();
        let key = d.key("/x/doc").unwrap();
        d.write_with(|w| if p.0.len() == 1 && p.0[0] == field(3) { w.at(t, key.clone()).path(p.clone()).insert(0, &[item]) } else { w.at(t, key.clone()).path(p.clone()).add(&item) }).unwrap();
    };
    for (name, p) in &spots {
        write(&a, p, "x");
        assert_ne!(a.get(t, doc.clone()).unwrap(), before, "{name}");
        a.undo(&scope).unwrap().unwrap();
        assert_eq!(a.get(t, doc.clone()).unwrap(), before, "{name}");
        // concurrent: b writes into the spot unseen, a writes and undoes, then they meet
        write(&b, p, "y");
        let b_only = b.get(t, doc.clone()).unwrap();
        write(&a, p, "x");
        a.undo(&scope).unwrap().unwrap();
        sync2(&a, &b);
        assert_eq!(a.get(t, doc.clone()).unwrap(), before, "{name}: b's concurrent write wiped");
        assert_eq!(b.get(t, doc.clone()).unwrap(), before, "{name}");
        // seen: b's write is held when a undoes, so only a's write goes
        write(&b, p, "y");
        sync2(&a, &b);
        write(&a, p, "x");

        a.undo(&scope).unwrap().unwrap();
        assert_eq!(a.get(t, doc.clone()).unwrap(), b_only, "{name}: b's held write stays");
        // back to the start for the next spot: b undoes its write (a's undone write's
        // tombstone carries no value, so it does not block the reset)
        sync2(&a, &b);
        b.undo(&scope).unwrap().unwrap();
        sync2(&a, &b);
        assert_eq!(a.get(t, doc.clone()).unwrap(), before, "{name}");
    }
}
