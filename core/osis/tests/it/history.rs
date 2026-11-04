//! An aspect's history through the API (notes/api.md History): pages, `on_history`, memory
//! commits, what a page says of what is not here; delete for everyone and purge by author.

use crate::common::*;
use osis::{ChangeId, CommitKind, Error, HistoryBody, HistoryEvent, HistoryFrom, Osis, Role, SyncScope, Tid, Value};
use osis_sim::world::World;
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

fn msgs() -> osis::Ak {
    ak("t:msgs.0")
}

fn s(x: &str) -> Value {
    Value::Str(x.into())
}

fn db_at(n: u64) -> Osis {
    crate::common::db(n)
}

fn thing(db: &Osis) -> Tid {
    db.write_with(|w| w.create(db.me())).unwrap()
}

fn say(db: &Osis, t: Tid, x: &str) -> ChangeId {
    let mut w = db.write();
    w.at(t, msgs()).set(&s(x)).unwrap();
    w.commit().unwrap().unwrap().id
}

fn watch(db: &Osis, t: Tid, k: osis::Ak) -> (osis::Subscription, Receiver<HistoryEvent<Value>>) {
    let (tx, rx) = channel();
    let sub = db.at(t, k).on_history(move |_, e| tx.send(e).unwrap()).unwrap();
    (sub, rx)
}

/// What the watch said since the last call.
fn heard(db: &Osis, rx: &Receiver<HistoryEvent<Value>>) -> Vec<HistoryEvent<Value>> {
    db.settle();
    rx.try_iter().collect()
}

// spec/permissions.md §5.2 (a valid commit's actor is its author), notes/api.md History: through the typed API a page carries value, author, times, kind and validity;
// the watch tells a new commit's entry with no read of a page.
#[test]
fn page_and_watch() {
    let db = db(1);
    let t = thing(&db);
    let (_sub, rx) = watch(&db, t, msgs());
    let a = say(&db, t, "one");
    let got = heard(&db, &rx);
    let [HistoryEvent::Commit { id, entry: Some(e) }] = got.as_slice() else { panic!("{got:?}") };
    assert_eq!(*id, a);
    assert_eq!((e.body.clone(), e.valid, e.commit.actor, e.kind), (HistoryBody::Held(Some(s("one"))), true, db.me(), CommitKind::Change));
    say(&db, t, "two");
    let page = db.at(t, msgs()).history(HistoryFrom::Newest, 10).unwrap();
    assert_eq!(page.entries.iter().map(|e| e.body.clone()).collect::<Vec<_>>(), vec![HistoryBody::Held(Some(s("two"))), HistoryBody::Held(Some(s("one")))]);
    assert!(!page.more);
    assert!(page.entries[0].commit.received.0 > 0);
    // a page past the bound ends early and says more
    for i in 0..osis::HISTORY_PAGE {
        say(&db, t, &format!("m{i}"));
    }
    let page = db.at(t, msgs()).history(HistoryFrom::Newest, usize::MAX).unwrap();
    assert_eq!(page.entries.len(), osis::HISTORY_PAGE);
    assert!(page.more);
    let next = db.at(t, msgs()).history(HistoryFrom::Before(page.entries.last().unwrap().pos()), 1).unwrap();
    assert_eq!(next.entries.len(), 1);
    // an unknown thing: empty, not an error
    let none = db.at(Tid::from_bytes([7; 15]), msgs()).history(HistoryFrom::Newest, 5).unwrap();
    assert!(none.entries.is_empty() && !none.more);
}

// spec/commits.md §5, notes/api.md History: delete for everyone: one commit's body goes for good and
// its entry stays as a tombstone; what the state reads does not change for a dead write; the
// request adds no entry to the aspect it purges; the watch tells it.
#[test]
fn purge_commit_is_delete_for_everyone_spec_commits_5() {
    let db = db(3);
    let t = thing(&db);
    let a = say(&db, t, "secret");
    let b = say(&db, t, "next");
    let (_sub, rx) = watch(&db, t, msgs());
    let mut w = db.write();
    w.at(t, msgs()).purge_commit(a).unwrap();
    let rq = w.commit().unwrap().unwrap().id;
    let page = db.at(t, msgs()).history(HistoryFrom::Oldest, 10).unwrap();
    assert_eq!(page.entries.len(), 2, "no entry for the request");
    assert_eq!(page.entries[0].commit.id, a);
    assert_eq!(page.entries[0].body, HistoryBody::Purged { by: rq, actor: Some(db.me()) });
    assert_eq!(page.entries[1].commit.id, b);
    assert_eq!(db.get(t, msgs()).unwrap(), Some(s("next")));
    let got = heard(&db, &rx);
    assert!(got.iter().any(|e| matches!(e, HistoryEvent::Commit { id, entry: Some(e) } if *id == a && matches!(e.body, HistoryBody::Purged { .. }))), "{got:?}");
    // an ephemeral batch has no delta to purge; a memory aspect takes none
    let mut w = db.write();
    assert!(matches!(w.at(t, ak("t:x.0~")).purge_author(db.me()), Err(Error::Invalid(_))));
}

// spec/permissions.md §8: a purge by author through the API: an admin's request drops a writer's
// bodies on every node, its own stay; and no write on the thing, no request (it could never hold a
// right, and nothing else in the batch would check).
#[test]
fn purge_author_through_the_api_spec_perm_8() {
    let mut w = World::new();
    let host = w.add_host();
    let (alice, _) = w.person(1, &[host]);
    let (bob, _) = w.person(2, &[host]);
    w.run();
    let card = bob.contact_card().unwrap();
    w.run();
    let b = w.until(alice.import_contact(&card), 1000, 10).unwrap();
    let g = alice
        .write_with(|x| {
            let g = x.create(alice.me())?;
            x.place(g, alice.home())?;
            x.make_group(g)?;
            Ok(g)
        })
        .unwrap();
    alice.sync(g, &[]).unwrap();
    alice.grant(g, b, Role::Read, Default::default()).unwrap();
    w.run();
    for r in bob.invite_requests().unwrap_or_default() {
        let _ = bob.accept_invite(r);
    }
    w.run();
    let mut x = bob.write();
    x.at(g, msgs()).purge_author(alice.me()).unwrap();
    assert!(matches!(x.commit(), Err(Error::Permission { needs: Role::Write, .. })), "a reader");
    alice.change_edge(g, b, Role::Write, Default::default()).unwrap();
    w.run();
    let flood = say(&bob, g, "junk");
    let own = say(&alice, g, "mine");
    w.run();
    let mut x = alice.write();
    x.at(g, msgs()).purge_author(bob.me()).unwrap();
    let rq = x.commit().unwrap().unwrap().id;
    w.run();
    for db in [&alice, &bob] {
        let page = db.at(g, msgs()).history(HistoryFrom::Oldest, 10).unwrap();
        let of = |c: ChangeId| page.entries.iter().find(|e| e.commit.id == c).unwrap().body.clone();
        assert_eq!(of(flood), HistoryBody::Purged { by: rq, actor: Some(alice.me()) });
        assert_eq!(of(own), HistoryBody::Held(Some(s("mine"))));
    }
}

// spec/sync.md §6, notes/api.md History (the seam for issues/partial-history-fetch.md): `complete` is false while a
// label carrying the thing has more to bring, so what is not listed is not fetched, not absent.
#[test]
fn page_says_when_it_may_miss_entries() {
    let mut w = World::new();
    let host = w.add_host();
    let (db, _) = w.person(1, &[host]);
    let t = db.write_with(|x| {
        let t = x.create(db.me())?;
        x.place(t, db.home())?;
        Ok(t)
    });
    let t = t.unwrap();
    say(&db, t, "x");
    assert!(!db.at(t, msgs()).history(HistoryFrom::Newest, 1).unwrap().complete, "still syncing");
    w.until(db.wait_synced(SyncScope::All, Duration::from_secs(60)), 1000, 10).unwrap();
    w.run();
    assert!(db.at(t, msgs()).history(HistoryFrom::Newest, 1).unwrap().complete);
    // a thing in no label: nothing to wait for
    let alone = db_at(4);
    let u = thing(&alone);
    assert!(alone.at(u, msgs()).history(HistoryFrom::Newest, 1).unwrap().complete);
}

// spec/sync.md §6: a new device reads the newest messages while older ones are on their way:
// `complete` false, then true, and every page's entries the newest there are.
#[test]
fn a_new_device_reads_newest_first_spec_sync_6() {
    const N: usize = 400;
    let mut w = World::new();
    let host = w.add_host();
    let (db, _) = w.person(1, &[host]);
    let t = db
        .write_with(|x| {
            let t = x.create(db.me())?;
            x.place(t, db.home())?;
            Ok(t)
        })
        .unwrap();
    // the thing's creation comes with its first message, which judging needs first
    say(&db, t, "first");
    for i in 0..N {
        say(&db, t, &format!("{i:05}"));
    }
    w.run();
    let join = Osis::pair(w.cfg(2, &[]), &db.pair_offer().unwrap()).unwrap();
    let (_, reply) = db.pair_accept(join.request()).unwrap();
    let phone = join.finish(&reply).unwrap();
    let mut part = false;
    for _ in 0..100_000 {
        let page = phone.at(t, msgs()).history(HistoryFrom::Newest, 10).unwrap();
        if !page.entries.is_empty() {
            let shown = page.entries.iter().filter(|e| e.body != HistoryBody::Held(Some(s("first"))));
            for (i, e) in shown.enumerate() {
                assert_eq!(e.body, HistoryBody::Held(Some(s(&format!("{:05}", N - 1 - i)))), "newest first");
            }
            if page.complete {
                break;
            }
            part = true;
        }
        // one hop; nothing queued: time for a tick
        if !w.step(None) {
            w.advance(1_000);
        }
    }
    assert!(part, "seen before it was complete");
    w.run();
    assert!(phone.at(t, msgs()).history(HistoryFrom::Newest, 1).unwrap().complete);
}

// spec/sync.md §9, notes/api.md History, notes/ephemeral.md: memory data has a history too: own batches at once,
// another node's memory commits with their author, and a commit gone (its expiry) is told as gone.
#[test]
fn memory_commits_read_and_tell_spec_sync_9() {
    let mut w = World::new();
    let host = w.add_host();
    let (alice, _) = w.person(1, &[host]);
    let (bob, _) = w.person(2, &[host]);
    w.run();
    let card = bob.contact_card().unwrap();
    w.run();
    let b = w.until(alice.import_contact(&card), 1000, 10).unwrap();
    let g = alice
        .write_with(|x| {
            let g = x.create(alice.me())?;
            x.place(g, alice.home())?;
            x.make_group(g)?;
            Ok(g)
        })
        .unwrap();
    alice.sync(g, &[]).unwrap();
    alice.grant(g, b, Role::Write, Default::default()).unwrap();
    w.run();
    let typing = ak("t:typing.0~");
    let (_sub, rx) = watch(&bob, g, typing.clone());
    let mut x = alice.write();
    x.at(g, typing.clone()).expires_in(Duration::from_secs(5)).set(&s("alice types")).unwrap();
    x.commit().unwrap();
    // at once for its writer
    let own = alice.at(g, typing.clone()).history(HistoryFrom::Newest, 5).unwrap();
    assert_eq!(own.entries.len(), 1);
    assert_eq!(own.entries[0].body, HistoryBody::Held(Some(s("alice types"))));
    assert_eq!(own.entries[0].kind, CommitKind::Ephemeral);
    w.run();
    let got = bob.at(g, typing.clone()).history(HistoryFrom::Newest, 5).unwrap();
    assert_eq!(got.entries.len(), 1, "{got:?}");
    assert_eq!((got.entries[0].commit.actor, got.entries[0].valid, got.entries[0].body.clone()), (alice.me(), true, HistoryBody::Held(Some(s("alice types")))));
    let id = got.entries[0].commit.id;
    assert!(heard(&bob, &rx).iter().any(|e| matches!(e, HistoryEvent::Commit { id: i, entry: Some(_) } if *i == id)));
    // its own batch and its commit are one entry at its writer
    assert_eq!(alice.at(g, typing.clone()).history(HistoryFrom::Newest, 5).unwrap().entries.len(), 1);
    w.advance(6_000);
    w.run();
    assert!(bob.at(g, typing.clone()).history(HistoryFrom::Newest, 5).unwrap().entries.is_empty());
    assert!(heard(&bob, &rx).iter().any(|e| matches!(e, HistoryEvent::Commit { id: i, entry: None } if *i == id)), "gone");
    assert!(alice.at(g, typing).history(HistoryFrom::Newest, 5).unwrap().entries.is_empty(), "its writer too");
}

// spec/data-model.md §6 (large values), notes/api.md History: a page is bounded in the bytes of its values, a link's once materialized, so
// it fits what a reply carries: it ends early, says more, and the next page goes on. A value above
// the bound alone reads as too large, its entry in its place.
#[test]
fn page_bound_counts_large_values() {
    let mut c = osis::Config::memory();
    c.materialize_limit = 3 << 20;
    let db = Osis::create(c).unwrap().0;
    let t = thing(&db);
    let k = ak("t:big.0");
    let put = |n: usize, b: u8| {
        db.write_with(|w| w.at(t, k.clone()).set(&Value::Bytes(vec![b; n]))).unwrap();
    };
    put(2 << 20, 1);
    put(2 << 20, 2);
    put(2 << 20, 3);
    let page = db.at(t, k.clone()).history(HistoryFrom::Oldest, 10).unwrap();
    assert_eq!(page.entries.len(), 2, "stops past the bound");
    assert!(page.more);
    assert_eq!(page.entries[0].body, HistoryBody::Held(Some(Value::Bytes(vec![1; 2 << 20]))), "its bytes, no link");
    let next = db.at(t, k.clone()).history(HistoryFrom::After(page.entries[1].pos()), 10).unwrap();
    assert_eq!(next.entries.len(), 1);
    assert!(!next.more);
    let last = next.entries[0].pos();
    put(4 << 20, 4);
    let huge = db.at(t, k.clone()).history(HistoryFrom::After(last), 10).unwrap();
    assert_eq!(huge.entries[0].body, HistoryBody::TooLarge { limit: 3 << 20 });
}

// spec/commits.md §5 (fixed retention, a request carries no `expires`): a required retention with
// an expiry on every aspect reaches no `purge.0`, so delete for everyone still works in a
// disappearing chat, and a kept-for-good one adds no permanent delta per delete.
#[test]
fn purge_answers_to_no_required_retention_spec_commits_5() {
    use osis::schema::core_types as ct;
    let db = db(11);
    let t = thing(&db);
    let a = say(&db, t, "x");
    let rules: ct::RequiredRules = [(String::new(), ct::Required::new(osis::Retention::default(), Some(60_000)))].into_iter().collect();
    db.write_with(|w| w.at(t, ct::REQUIRED).set(&rules)).unwrap();
    let mut w = db.write();
    w.at(t, msgs()).purge_commit(a).unwrap();
    let rq = w.commit().unwrap().unwrap().id;
    assert_eq!(db.at(t, msgs()).history(HistoryFrom::Oldest, 1).unwrap().entries[0].body, HistoryBody::Purged { by: rq, actor: Some(db.me()) });
}

// spec/commits.md §5 (a writer does not undo `required.0^`), notes/api.md `knows`: a required retention is no content: a delete leaves it in force and the thing reads deleted; undoing the creation likewise
#[test]
fn required_is_no_content_spec_commits_5() {
    use osis::schema::core_types as ct;
    let db = db(12);
    let rules = ct::RequiredRules { keep: true, ..Default::default() };
    let t = thing(&db);
    say(&db, t, "x");
    db.write_with(|w| w.at(t, ct::REQUIRED).set(&rules)).unwrap();
    db.write_with(|w| w.delete(t)).unwrap();
    assert!(!db.knows(t), "deleted");
    assert_eq!(db.get(t, ct::REQUIRED).unwrap(), Some(rules.clone()), "still in force");
    let u = db.write_with(|w| { let u = w.create(db.me())?; w.at(u, msgs()).set(&s("x"))?; w.at(u, ct::REQUIRED).set(&rules)?; Ok(u) }).unwrap();
    db.undo(&osis::Scope::Thing(u)).unwrap();
    assert!(!db.knows(u), "undone");
    assert_eq!(db.get(u, ct::REQUIRED).unwrap(), Some(rules));
}
