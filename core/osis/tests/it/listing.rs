//! Commit listings and their listeners (notes/api.md Commits): which parts a commit shows (in the
//! read, kept by history until its bound, a purge tombstone, this node's own invalid write), at an
//! aspect, a thing and a group, typed and untyped; pages, `complete`, memory commits; delete for
//! everyone and purge by author.

use crate::common::TestWrites as _;
use osis::internals::Internals as _;
use crate::common::*;
use osis::{Body, CommitEvent, CommitFrom, CommitId, CommitKind, CommitQuery, Error, Osis, Role, Scope, SyncScope, Tid, Value};
use osis_sim::world::World;
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

fn msg() -> osis::Ak {
    ak("t:msg.0")
}

fn untyped(k: osis::Ak) -> osis::DynamicAspectKey {
    osis::DynamicAspectKey::untyped(k)
}

fn s(x: &str) -> Value {
    Value::Str(x.into())
}

fn db_at(n: u64) -> Osis {
    crate::common::db(n)
}

fn thing(db: &Osis) -> Tid {
    db.commit_with(|w| w.create()).unwrap()
}

fn forever() -> osis::Retention {
    osis::Retention { history: Some(osis::History::FOREVER), ..Default::default() }
}

/// A write of `x` on `t`'s `msg`, its history kept for good: every one stays listed.
fn say(db: &Osis, t: Tid, x: &str) -> CommitId {
    let mut w = db.write();
    w.at(t, untyped(msg())).retention(forever()).set(&s(x)).unwrap();
    w.commit().unwrap().unwrap().stamp.id
}

/// The bodies of `t`'s `k` listed, oldest first.
fn bodies(db: &Osis, t: Tid, k: &osis::Ak) -> Vec<Body<Value>> {
    db.at(t, untyped(k.clone())).writes(&page(CommitFrom::Oldest, 100)).unwrap().commits.iter().map(|c| part(c, t, k).body).collect()
}

fn watch(db: &Osis, t: Tid, k: osis::Ak) -> (osis::Subscription, Receiver<CommitEvent>) {
    let (tx, rx) = channel();
    let sub = db.at(t, untyped(k)).on_write(move |_, e| tx.send(e).unwrap()).unwrap();
    (sub, rx)
}

/// What the listener said since the last call.
fn heard(db: &Osis, rx: &Receiver<CommitEvent>) -> Vec<CommitEvent> {
    db.settle();
    rx.try_iter().collect()
}

/// The commits a listener heard of, listed or not.
fn ids(evs: &[CommitEvent]) -> Vec<(CommitId, bool)> {
    evs.iter().filter_map(|e| if let CommitEvent::Commit { id, commit } = e { Some((*id, commit.is_some())) } else { None }).collect()
}

// spec/permissions.md §5.2 (a valid commit's actor is its author), notes/api.md Commits: through
// the API a page carries value, author, times, kind and validity; the listener tells a new commit
// with no read of a page; a page past the cap ends early and says more.
#[test]
fn page_and_listener() {
    let db = db(1);
    let t = thing(&db);
    let (_sub, rx) = watch(&db, t, msg());
    let a = say(&db, t, "one");
    let got = heard(&db, &rx);
    let [CommitEvent::Commit { id, commit: Some(c) }] = got.as_slice() else { panic!("{got:?}") };
    assert_eq!(*id, a);
    let p = part(c, t, &msg());
    assert_eq!((p.body, p.valid, c.stamp.actor, c.kind), (Body::Held(Some(s("one"))), true, db.me(), CommitKind::Content));
    say(&db, t, "two");
    let got = db.at(t, untyped(msg())).writes(&page(CommitFrom::Newest, 10)).unwrap();
    assert_eq!(got.commits.iter().map(|c| part(c, t, &msg()).body).collect::<Vec<_>>(), vec![Body::Held(Some(s("two"))), Body::Held(Some(s("one")))]);
    assert!(!got.more);
    assert!(got.commits[0].stamp.received.0 > 0);
    for i in 0..osis::internals::COMMIT_PAGE {
        say(&db, t, &format!("m{i}"));
    }
    let got = db.at(t, untyped(msg())).writes(&page(CommitFrom::Newest, usize::MAX)).unwrap();
    assert_eq!(got.commits.len(), osis::internals::COMMIT_PAGE);
    assert!(got.more);
    let next = db.at(t, untyped(msg())).writes(&page(CommitFrom::Before(got.commits.last().unwrap().pos()), 1)).unwrap();
    assert_eq!(next.commits.len(), 1);
    // an unknown thing: empty, not an error
    let none = db.at(Tid::from_bytes([7; 15]), untyped(msg())).writes(&page(CommitFrom::Newest, 5)).unwrap();
    assert!(none.commits.is_empty() && !none.more);
}

// spec/commits.md §7 (Listed parts), notes/api.md Commits: a register keeping no history lists only its
// live write; one keeping history, declared or per write, lists every write until its keep bound,
// then only the live one again; a signal key lists no writes, a value key no fires.
#[test]
fn listed_while_in_read_or_kept_api_commits() {
    let c = clock();
    let db = osis::internals::create(cfg(1, osis::MemStore::new(), &c)).unwrap();
    keep_day(&db, &["t:kept.0"]);
    let t = thing(&db);
    let (plain, decl) = (ak("t:plain.0"), ak("t:kept.0"));
    for v in ["a", "b", "c"] {
        db.commit_set(t, untyped(plain.clone()), &s(v)).unwrap();
        db.commit_set(t, kept(&db, &decl), &s(v)).unwrap();
        say(&db, t, v);
    }
    let held = |v: &str| Body::Held(Some(s(v)));
    assert_eq!(bodies(&db, t, &plain), vec![held("c")], "no history: the live write alone");
    assert_eq!(bodies(&db, t, &decl), vec![held("a"), held("b"), held("c")], "the schema's keep_history");
    assert_eq!(bodies(&db, t, &msg()), vec![held("a"), held("b"), held("c")], "a per-write retention");
    c.advance(2 * 86_400_000);
    assert_eq!(bodies(&db, t, &decl), vec![held("c")], "past the bound: the live write alone");
    assert_eq!(bodies(&db, t, &msg()).len(), 3, "forever");
    // listing an aspect whose writes keep no history is no error; nor a crossing of kinds
    assert!(db.at(t, untyped(ak("t:log~0"))).writes(&CommitQuery::default()).unwrap().commits.is_empty());
    assert!(db.at(t, untyped(plain.clone())).fired(&CommitQuery::default()).unwrap().commits.is_empty());
}

// spec/commits.md §7 (Listed parts), notes/api.md Commits (listeners): a replaced part leaving
// the listing at its keep bound is told, to a listener added before its replacement and to one
// added after, once; no keep-bound timer is armed for an aspect no listener is on, or for one
// whose writes keep no history.
#[test]
fn kept_part_is_told_leaving_at_its_bound_api_commits() {
    let c = clock();
    let db = osis::internals::create(cfg(1, osis::MemStore::new(), &c)).unwrap();
    keep_day(&db, &["t:kept.0"]);
    let t = thing(&db);
    let (k, plain) = (ak("t:kept.0"), ak("t:plain.0"));
    let timer = || db.engine(|e| e.next_timer().unwrap());
    let x = commit_with(&db, |w| w.at(t, kept(&db, &k)).set(&s("x"))).stamp.id;
    commit_with(&db, |w| w.at(t, kept(&db, &k)).set(&s("y")));
    assert_eq!(timer(), None, "no listener: no timer");
    let p = thing(&db);
    let (_p, prx) = watch(&db, p, plain.clone());
    for v in ["x", "y"] {
        db.commit_set(p, untyped(plain.clone()), &s(v)).unwrap();
    }
    assert_eq!(timer(), None, "no history kept: no timer");
    let u = thing(&db);
    let (_before, rx) = watch(&db, u, k.clone());
    let a = commit_with(&db, |w| w.at(u, kept(&db, &k)).set(&s("a"))).stamp.id;
    commit_with(&db, |w| w.at(u, kept(&db, &k)).set(&s("b")));
    // replaced while no listener was on it
    let (_late, rx2) = watch(&db, t, k.clone());
    heard(&db, &rx);
    heard(&db, &prx);
    c.advance(2 * 86_400_000);
    db.engine(|e| e.tick().unwrap());
    assert_eq!(ids(&heard(&db, &rx)), vec![(a, false)], "told leaving");
    assert_eq!(ids(&heard(&db, &rx2)), vec![(x, false)], "to a listener added after its replacement too");
    assert_eq!(bodies(&db, u, &k), vec![Body::Held(Some(s("b")))], "as a page reads");
    commit_with(&db, |w| w.at(u, kept(&db, &k)).set(&s("d")));
    assert!(ids(&heard(&db, &rx)).iter().all(|x| x.0 != a), "told once");
}

// spec/commits.md §7 (Listed parts), notes/api.md Commits (listeners): a write replacing a part
// that keeps no history tells that part's commit leaving the listing, at the aspect and at the
// thing's group; a write beside it tells nothing more.
#[test]
fn replaced_unkept_part_is_told_leaving_api_commits() {
    let db = db(4);
    let t = thing(&db);
    let g = db.commit_with(|w| {
        let g = w.create()?;
        w.group(g).add(osis::Member::Item(t))?;
        Ok(g)
    })
    .unwrap();
    let plain = ak("t:plain.0");
    let first = commit_with(&db, |w| w.at(t, untyped(plain.clone())).set(&s("a"))).stamp.id;
    let (_sub, rx) = watch(&db, t, plain.clone());
    let (gtx, grx) = channel();
    let _g = db.on_write(&Scope::Group(g), move |_, e| gtx.send(e).unwrap()).unwrap();
    let second = commit_with(&db, |w| w.at(t, untyped(plain.clone())).set(&s("b"))).stamp.id;
    let mut want = vec![(first, false), (second, true)];
    want.sort();
    let sorted = |mut v: Vec<(CommitId, bool)>| {
        v.sort();
        v
    };
    assert_eq!(sorted(ids(&heard(&db, &rx))), want, "the replaced commit leaves, the new one comes");
    assert_eq!(sorted(ids(&heard(&db, &grx))), want, "at the group too");
    let ids_listed: Vec<CommitId> = db.at(t, untyped(plain.clone())).writes(&CommitQuery::default()).unwrap().commits.iter().map(|c| c.stamp.id).collect();
    assert_eq!(ids_listed, vec![second], "as a page reads");
    let beside = say(&db, t, "beside");
    assert!(heard(&db, &rx).is_empty(), "nothing at the register");
    assert_eq!(ids(&heard(&db, &grx)), vec![(beside, true)], "the group's new commit alone");
}

// spec: none (API surface); notes/api.md Commits (the commit): a commit writing two things lists at an aspect of one with
// both parts; `at` decodes a part typed, a mismatching body reading `Held(None)` with a `Mismatch`
// diagnostic; and `w.commit()` returns the commit as a listing then shows it.
#[test]
fn a_commit_shows_every_part_api_commits() {
    let db = db(2);
    db.register_schema("n.osis", "revision 1;\nkeep_history(1d) aspect t:n.0: int;\n").unwrap();
    let n = db.aspect_key("t:n.0").unwrap();
    let (a, b) = (thing(&db), thing(&db));
    let mut w = db.write();
    w.at(a, untyped(msg())).set(&s("on a")).unwrap();
    w.at(b, n.clone()).set(&Value::Int(5)).unwrap();
    let made = w.commit().unwrap().unwrap();
    let got = db.at(a, untyped(msg())).writes(&CommitQuery::default()).unwrap().commits;
    assert_eq!(got, vec![made.clone()], "what the write returned");
    let c = &got[0];
    let mut parts: Vec<_> = c.parts().map(|(t, k, p)| (t, k.as_str().to_string(), p.body.clone())).collect();
    parts.sort_by_key(|p| p.1.clone());
    assert_eq!(parts, vec![(a, "t:msg.0".to_string(), Body::Held(Some(s("on a")))), (b, "t:n.0".to_string(), Body::Held(Some(Value::Int(5))))]);
    assert_eq!(c.at(b, n.clone()).unwrap().body, Body::Held(Some(Value::Int(5))), "typed");
    assert_eq!(c.at(a, n.clone()), None, "no part there");
    assert_eq!(db.writes(&Scope::Thing(b), &CommitQuery::default()).unwrap().commits.first(), Some(&made), "listed at the other thing too");
    // a mismatching body
    let (tx, rx) = channel();
    let _d = db.on_diagnostic(move |_, d| tx.send(d).unwrap()).unwrap();
    let odd = commit_with(&db, |w| w.at(b, untyped(ak("t:n.0"))).set(&s("not an int")));
    let got = db.at(b, n.clone()).writes(&page(CommitFrom::Newest, 1)).unwrap().commits;
    assert_eq!(got[0].stamp.id, odd.stamp.id);
    assert_eq!(got[0].at(b, n.clone()).unwrap().body, Body::Held(None));
    assert_eq!(part(&got[0], b, &ak("t:n.0")).body, Body::Held(Some(s("not an int"))), "the untyped key shows it");
    db.settle();
    assert!(rx.try_iter().any(|d| matches!(d, osis::Diagnostic::Mismatch { .. })), "a mismatch told");
}

// spec/commits.md §5 Signals (heard only as listed at the signal), notes/api.md Commits (listeners at a scope): a thing listener hears a commit touching the thing
// and not one beside it, nor a signal fired on it; a group listener hears a member's commit.
#[test]
fn scope_listeners_api_commits() {
    let db = db(3);
    let (t, other) = (thing(&db), thing(&db));
    let g = db.commit_with(|w| {
        let g = w.create()?;
        w.group(g).add(osis::Member::Item(t))?;
        Ok(g)
    })
    .unwrap();
    let (tx, rx) = channel();
    let _t = db.on_write(&Scope::Thing(t), move |_, e| tx.send(e).unwrap()).unwrap();
    let (gtx, grx) = channel();
    let _g = db.on_write(&Scope::Group(g), move |_, e| gtx.send(e).unwrap()).unwrap();
    let mine = say(&db, t, "on t");
    say(&db, other, "beside");
    let log = untyped(ak("t:log~0"));
    commit_with(&db, |w| w.at(t, log.clone()).retention(forever()).fire(&s("ping")));
    assert_eq!(ids(&heard(&db, &rx)), vec![(mine, true)], "its commit, nothing beside, no signal");
    assert_eq!(ids(&heard(&db, &grx)), vec![(mine, true)], "a member's commit");
    assert_eq!(db.at(t, log).fired(&CommitQuery::default()).unwrap().commits.len(), 1, "the signal lists at its key");
}

// spec/permissions.md §5.1, §5.2, notes/api.md Commits: a write stamped after its writer's role
// ended turns invalid: another node lists it nowhere, its own node lists it, marked.
#[test]
fn invalid_listed_only_at_its_writer_spec_perm_5() {
    let mut w = World::new();
    let host = w.add_host();
    let alice = w.account(1, &[host]);
    let bob = w.account(2, &[host]);
    w.run();
    let card = bob.contact_card().unwrap();
    w.run();
    let b = w.until(alice.import_contact(&card), 1000, 10).unwrap();
    let g = alice
        .commit_with(|x| {
            let g = x.create()?;
            x.group(alice.home()).add(osis::Member::Item(g))?;
            Ok(g)
        })
        .unwrap();
    alice.sync(g, &[]).unwrap();
    alice.grant(g, b, Role::Write, Default::default()).unwrap();
    w.run();
    for r in bob.invite_requests().unwrap_or_default() {
        let _ = bob.accept_invite(r);
    }
    w.run();
    let seen = say(&bob, g, "seen");
    w.run();
    w.set_online(&bob, false);
    w.advance(1000);
    // a kept copy: bob still reads what he held
    alice.set_role(g, b, None, osis::SetRoleOpts { retain_copy: Some(true) }).unwrap();
    w.run();
    let late = say(&bob, g, "late");
    w.set_online(&bob, true);
    w.advance(60_000);
    w.run();
    let listed_at = |db: &Osis| db.at(g, untyped(msg())).writes(&CommitQuery::default()).unwrap().commits.into_iter().map(|c| (c.stamp.id, part(&c, g, &msg()).valid)).collect::<Vec<_>>();
    assert!(!listed_at(&alice).iter().any(|x| x.0 == late), "another node's invalid write");
    assert!(listed_at(&alice).contains(&(seen, true)));
    assert!(listed_at(&bob).contains(&(late, false)), "its own, marked: {:?}", listed_at(&bob));
}

// spec/commits.md §5, notes/api.md Commits: delete for everyone: one commit's body goes for good
// and it stays listed as a tombstone; what the state reads does not change for a dead write; the
// request adds no commit to the aspect it purges; the listener tells it.
#[test]
fn purge_commit_is_delete_for_everyone_spec_commits_5() {
    let db = db(3);
    let t = thing(&db);
    let a = say(&db, t, "secret");
    let b = say(&db, t, "next");
    let (_sub, rx) = watch(&db, t, msg());
    let mut w = db.write();
    w.at(t, untyped(msg())).purge(osis::Purge::Commit(a)).unwrap();
    let rq = w.commit().unwrap().unwrap().stamp.id;
    let got = db.at(t, untyped(msg())).writes(&page(CommitFrom::Oldest, 10)).unwrap();
    assert_eq!(got.commits.len(), 2, "no commit for the request");
    assert_eq!(got.commits[0].stamp.id, a);
    assert_eq!(part(&got.commits[0], t, &msg()).body, Body::Purged { by: rq, actor: Some(db.me()) });
    assert_eq!(got.commits[1].stamp.id, b);
    assert_eq!(db.at(t, untyped(msg())).get().unwrap(), Some(s("next")));
    let evs = heard(&db, &rx);
    assert!(evs.iter().any(|e| matches!(e, CommitEvent::Commit { id, commit: Some(c) } if *id == a && matches!(part(c, t, &msg()).body, Body::Purged { .. }))), "{evs:?}");
    // a register's live write purged, no history kept: still listed, as purged
    let x = commit_with(&db, |w| w.at(t, untyped(ak("t:reg.0"))).set(&s("x")));
    commit_with(&db, |w| w.at(t, untyped(ak("t:reg.0"))).purge(osis::Purge::Commit(x.stamp.id)));
    assert!(matches!(bodies(&db, t, &ak("t:reg.0"))[..], [Body::Purged { .. }]));
    // an ephemeral commit has no delta to purge; a memory aspect takes none
    let mut w = db.write();
    assert!(matches!(w.at(t, untyped(ak("t:x+.0"))).purge(osis::Purge::Author(db.me())), Err(Error::Invalid(_))));
}

// spec/permissions.md §6: a purge by author through the API: an admin's request drops a writer's
// bodies on every node, its own stay; and no write on the thing, no request (it could never hold a
// right, and nothing else in the commit would check).
#[test]
fn purge_author_through_the_api_spec_perm_6() {
    let (mut w, alice, bob, b, g) = alice_admits_bob();
    let mut x = bob.write();
    x.at(g, untyped(msg())).purge(osis::Purge::Author(alice.me())).unwrap();
    assert!(matches!(x.commit(), Err(Error::Permission { needs: Role::Write, .. })), "a reader");
    alice.grant(g, b, Role::Write, Default::default()).unwrap();
    w.run();
    let flood = say(&bob, g, "junk");
    let own = say(&alice, g, "mine");
    w.run();
    let mut x = alice.write();
    x.at(g, untyped(msg())).purge(osis::Purge::Author(bob.me())).unwrap();
    let rq = x.commit().unwrap().unwrap().stamp.id;
    w.run();
    for db in [&alice, &bob] {
        let got = db.at(g, untyped(msg())).writes(&page(CommitFrom::Oldest, 10)).unwrap();
        let of = |c: CommitId| part(got.commits.iter().find(|e| e.stamp.id == c).unwrap(), g, &msg()).body;
        assert_eq!(of(flood), Body::Purged { by: rq, actor: Some(alice.me()) });
        assert_eq!(of(own), Body::Held(Some(s("mine"))));
    }
}

/// Alice's synced thing `g`, Bob (actor `b`) a reader of it.
fn alice_admits_bob() -> (World, Osis, Osis, Tid, Tid) {
    let mut w = World::new();
    let host = w.add_host();
    let alice = w.account(1, &[host]);
    let bob = w.account(2, &[host]);
    w.run();
    let card = bob.contact_card().unwrap();
    w.run();
    let b = w.until(alice.import_contact(&card), 1000, 10).unwrap();
    let mut x = alice.write();
    let g = x.create().unwrap();
    x.group(alice.home()).add(osis::Member::Item(g)).unwrap();
    x.commit().unwrap();
    alice.sync(g, &[]).unwrap();
    alice.grant(g, b, Role::Read, Default::default()).unwrap();
    w.run();
    for r in bob.invite_requests().unwrap_or_default() {
        let _ = bob.accept_invite(r);
    }
    w.run();
    (w, alice, bob, b, g)
}

// spec/permissions.md §6, notes/api-design.md (rights are checked locally before signing): a
// request whose purge rights would drop none of the held deltas it names is refused with
// `Permission` and nothing is sent; one dropping any of them is written. The default purge set is
// author or admin: a writer purges its own writes, the admin anyone's.
#[test]
fn purge_without_the_right_is_refused_spec_perm_6() {
    let (mut w, alice, bob, b, g) = alice_admits_bob();
    alice.grant(g, b, Role::Write, Default::default()).unwrap();
    w.run();
    let hers = say(&alice, g, "hers");
    w.run();
    let refused = |what: osis::Purge| {
        let mut x = bob.write();
        x.at(g, untyped(msg())).purge(what).unwrap();
        matches!(x.commit(), Err(Error::Permission { tid, .. }) if tid == g)
    };
    assert!(refused(osis::Purge::Commit(hers)), "another's write by commit");
    assert!(refused(osis::Purge::Author(alice.me())), "another's writes by author");
    assert!(refused(osis::Purge::All), "the aspect holding only another's writes");
    let his = say(&bob, g, "his");
    w.run();
    assert!(refused(osis::Purge::Author(alice.me())), "still none of his");
    let mut x = bob.write();
    x.at(g, untyped(msg())).purge(osis::Purge::Commit(his)).unwrap();
    let own = x.commit().unwrap().unwrap().stamp.id;
    let mut x = alice.write();
    x.at(g, untyped(msg())).purge(osis::Purge::Commit(hers)).unwrap();
    x.commit().unwrap();
    w.run();
    for db in [&alice, &bob] {
        let got = db.at(g, untyped(msg())).writes(&page(CommitFrom::Oldest, 10)).unwrap();
        let bodies: Vec<Body<Value>> = got.commits.iter().map(|c| part(c, g, &msg()).body).collect();
        assert!(matches!(bodies.as_slice(), [Body::Purged { .. }, Body::Purged { by, .. }] if *by == own), "{bodies:?}");
    }
}

// spec/sync.md §6, notes/api.md Commits (the seam for issues/partial-history-fetch.md): `complete` is false while a
// sync ID carrying the thing has more to bring from a connected node; a sync ID this node made has
// nothing to bring before any pass.
#[test]
fn page_says_when_it_may_miss_commits() {
    let mut w = World::new();
    let host = w.add_host();
    let db = w.account(1, &[host]);
    let t = db.commit_with(|x| {
        let t = x.create()?;
        x.group(db.home()).add(osis::Member::Item(t))?;
        Ok(t)
    });
    let t = t.unwrap();
    say(&db, t, "x");
    let newest = |db: &Osis, t| db.at(t, untyped(msg())).writes(&page(CommitFrom::Newest, 1)).unwrap();
    assert!(newest(&db, t).complete, "a sync ID it made: nothing known is missing");
    w.until(db.wait_synced(SyncScope::All), 1000, 10).unwrap();
    w.run();
    assert!(newest(&db, t).complete);
    // a thing in no label: nothing to wait for
    let alone = db_at(4);
    let u = thing(&alone);
    assert!(newest(&alone, u).complete);
}

// spec/sync.md §6: a new node reads the newest messages while older ones are on their way:
// `complete` false, then true, and every page's commits the newest there are.
#[test]
fn a_new_node_reads_newest_first_spec_sync_6() {
    const N: usize = 400;
    let mut w = World::new();
    let host = w.add_host();
    let db = w.account(1, &[host]);
    let mut x = db.write();
    let t = x.create().unwrap();
    x.group(db.home()).add(osis::Member::Item(t)).unwrap();
    x.commit().unwrap();
    // the thing's creation comes with its first message, which judging needs first
    say(&db, t, "first");
    for i in 0..N {
        say(&db, t, &format!("{i:05}"));
    }
    w.run();
    let join = osis::internals::pair(w.cfg(2, &[]), &db.pair_offer().unwrap()).unwrap();
    let (_, reply) = db.pair_accept(join.request()).unwrap();
    let phone = join.finish(&reply).unwrap();
    let mut partly = false;
    for _ in 0..100_000 {
        let got = phone.at(t, untyped(msg())).writes(&page(CommitFrom::Newest, 10)).unwrap();
        if !got.commits.is_empty() {
            let shown = got.commits.iter().map(|c| part(c, t, &msg()).body).filter(|b| *b != Body::Held(Some(s("first"))));
            for (i, b) in shown.enumerate() {
                assert_eq!(b, Body::Held(Some(s(&format!("{:05}", N - 1 - i)))), "newest first");
            }
            if got.complete {
                break;
            }
            partly = true;
        }
        // one hop; nothing queued: time for a tick
        if !w.step(None) {
            w.advance(1_000);
        }
    }
    assert!(partly, "seen before it was complete");
    w.run();
    assert!(phone.at(t, untyped(msg())).writes(&page(CommitFrom::Newest, 1)).unwrap().complete);
}

// spec/sync.md §9, notes/api.md Commits, notes/ephemeral.md: memory commits list too: own commits
// at once, another node's with their author; an expired one is listed no more, and the listener
// says so (spec/crdt.md §4.7: held value-less).
#[test]
fn memory_commits_list_and_tell_spec_sync_9() {
    let mut w = World::new();
    let host = w.add_host();
    let alice = w.account(1, &[host]);
    let bob = w.account(2, &[host]);
    w.run();
    let card = bob.contact_card().unwrap();
    w.run();
    let b = w.until(alice.import_contact(&card), 1000, 10).unwrap();
    let mut x = alice.write();
    let g = x.create().unwrap();
    x.group(alice.home()).add(osis::Member::Item(g)).unwrap();
    x.commit().unwrap();
    alice.sync(g, &[]).unwrap();
    alice.grant(g, b, Role::Write, Default::default()).unwrap();
    w.run();
    let typing = ak("t:typing+.0");
    let (_sub, rx) = watch(&bob, g, typing.clone());
    let mut x = alice.write();
    x.expires(osis::Expiry::In(Duration::from_secs(5)));
    x.at(g, untyped(typing.clone())).set(&s("alice types")).unwrap();
    x.commit().unwrap();
    let list = |a: &Osis| a.at(g, untyped(typing.clone())).writes(&page(CommitFrom::Newest, 5)).unwrap().commits;
    // at once for its writer
    let own = list(&alice);
    assert_eq!(own.len(), 1);
    assert_eq!(part(&own[0], g, &typing).body, Body::Held(Some(s("alice types"))));
    assert_eq!(own[0].kind, CommitKind::Content);
    w.run();
    let got = list(&bob);
    assert_eq!(got.len(), 1, "{got:?}");
    let p = part(&got[0], g, &typing);
    assert_eq!((got[0].stamp.actor, p.valid, p.body), (alice.me(), true, Body::Held(Some(s("alice types")))));
    let id = got[0].stamp.id;
    assert!(ids(&heard(&bob, &rx)).contains(&(id, true)));
    w.advance(6_000);
    w.run();
    assert!(list(&bob).is_empty(), "expired");
    assert!(ids(&heard(&bob, &rx)).contains(&(id, false)), "told: listed no more");
    assert!(list(&alice).is_empty(), "its writer too");
}

// spec/data-model.md §6 (large values), notes/api.md Commits: a page is bounded in the bytes of its values, a link's once materialized, so
// it fits what a reply carries: it ends early, says more, and the next page goes on. A value above
// the bound alone reads as too large, its commit in its place.
#[test]
fn page_bound_counts_large_values() {
    let mut c = osis::internals::Opening::memory();
    c.app.read_limit = 3 << 20;
    let db = osis::internals::create(c).unwrap();
    let t = thing(&db);
    let k = ak("t:big.0");
    let put = |n: usize, b: u8| {
        commit_with(&db, |w| w.at(t, untyped(k.clone())).retention(forever()).set(&Value::Bytes(vec![b; n])));
    };
    put(2 << 20, 1);
    put(2 << 20, 2);
    put(2 << 20, 3);
    let list = |from| db.at(t, untyped(k.clone())).writes(&page(from, 10)).unwrap();
    let got = list(CommitFrom::Oldest);
    assert_eq!(got.commits.len(), 2, "stops past the bound");
    assert!(got.more);
    assert_eq!(part(&got.commits[0], t, &k).body, Body::Held(Some(Value::Bytes(vec![1; 2 << 20]))), "its bytes, no link");
    let next = list(CommitFrom::After(got.commits[1].pos()));
    assert_eq!(next.commits.len(), 1);
    assert!(!next.more);
    let last = next.commits[0].pos();
    put(4 << 20, 4);
    let huge = list(CommitFrom::After(last));
    assert_eq!(part(&huge.commits[0], t, &k).body, Body::TooLarge { limit: 3 << 20 });
}

// spec/commits.md §5 (fixed retention, a request carries no `expires`): a required retention with
// an expiry on every aspect reaches no `purge.0`, so delete for everyone still works in a
// disappearing chat, and a kept-for-good one adds no permanent delta per delete.
#[test]
fn purge_answers_to_no_required_retention_spec_commits_5() {
    use osis::internals::schema::core_types as ct;
    let db = db(11);
    let t = thing(&db);
    let a = say(&db, t, "x");
    let rules = ct::RequiredRules { default: Some(ct::Required::new(osis::internals::schema::Retention::default(), Some(60_000))), ..Default::default() };
    db.commit_set(t, ct::REQUIRED, &rules).unwrap();
    let mut w = db.write();
    w.at(t, osis::DynamicAspectKey::untyped(msg())).purge(osis::Purge::Commit(a)).unwrap();
    let rq = w.commit().unwrap().unwrap().stamp.id;
    let got = db.at(t, untyped(msg())).writes(&page(CommitFrom::Oldest, 1)).unwrap();
    assert_eq!(part(&got.commits[0], t, &msg()).body, Body::Purged { by: rq, actor: Some(db.me()) });
}

// spec/commits.md §5 (a writer does not undo `required^.0`), notes/api.md `has_content`: a required retention is no content: a delete leaves it in force and the thing reads deleted; undoing the creation likewise
#[test]
fn required_is_no_content_spec_commits_5() {
    use osis::internals::schema::core_types as ct;
    let db = db(12);
    let rules = ct::RequiredRules { retain: true, ..Default::default() };
    let t = thing(&db);
    say(&db, t, "x");
    db.commit_set(t, ct::REQUIRED, &rules).unwrap();
    let mut w = db.write();
    w.delete(t).unwrap();
    w.commit().unwrap();
    assert!(!db.has_content(t).unwrap(), "deleted");
    assert_eq!(db.at(t, ct::REQUIRED).get().unwrap(), Some(rules.clone()), "still in force");
    let mut w = db.write();
    let u = w.create().unwrap();
    w.at(u, osis::DynamicAspectKey::untyped(msg())).set(&s("x")).unwrap();
    w.at(u, ct::REQUIRED).set(&rules).unwrap();
    w.commit().unwrap();
    db.undo(&osis::Scope::Thing(u)).unwrap();
    assert!(!db.has_content(u).unwrap(), "undone");
    assert_eq!(db.at(u, ct::REQUIRED).get().unwrap(), Some(rules));
}

// spec/commits.md §5, §6: a delta answers to its thing's required retention, its reset too, so a delete
// of a thing whose aspects (or groups) fall under different rules is several commits' work: refused,
// telling the app to do the rest first, and then the delete goes through. Each rule alike: expiry, `nobody`.
#[test]
fn delete_under_required_rules_says_what_to_do_spec_commits_6() {
    use osis::internals::schema::core_types as ct;
    let nobody = osis::internals::schema::Retention { by: osis::PurgeBy::Nobody, history: Some(osis::internals::schema::History::FOREVER) };
    let rule = [ct::Required::new(osis::internals::schema::Retention::default(), Some(60_000)), ct::Required::new(nobody, None)];
    for (i, r) in rule.into_iter().enumerate() {
        let db = db_at(50 + i as u64);
        let t = db.commit_with(|w| w.create()).unwrap();
        let rules = ct::RequiredRules { rules: [(osis::Ak::new("app:m.0").unwrap(), r)].into(), default: Some(ct::Required::new(osis::internals::schema::Retention::default(), None)), retain: false };
        db.commit_set(t, ct::REQUIRED, &rules).unwrap();
        let (m, plain) = (osis::DynamicAspectKey::untyped(osis::Ak::new("app:m.0").unwrap()), osis::DynamicAspectKey::untyped(osis::Ak::new("app:s.0").unwrap()));
        db.commit_set(t, m.clone(), &s("x")).unwrap();
        db.commit_set(t, plain.clone(), &s("y")).unwrap();
        assert!(matches!(db.commit_with(|w| w.delete(t)), Err(Error::Invalid(e)) if e.contains("delete") && e.contains("first") && !e.contains("separate")));
        assert!(db.has_content(t).unwrap(), "nothing applied");
        db.commit_with(|w| w.at(t, m).remove()).unwrap();
        db.commit_with(|w| w.delete(t)).unwrap();
        assert!(!db.has_content(t).unwrap());
    }
    // the group's removal goes first likewise, when the thing's own writes expire
    let db = db_at(52);
    let g = thing(&db);
    let t = thing(&db);
    db.commit_set(g, osis::DynamicAspectKey::untyped(osis::Ak::new("app:s.0").unwrap()), &s("y")).unwrap();
    db.commit_set(t, osis::DynamicAspectKey::untyped(osis::Ak::new("app:s.0").unwrap()), &s("y")).unwrap();
    db.commit_with(|w| w.group(g).add(osis::Member::Item(t))).unwrap();
    let rules = ct::RequiredRules { default: Some(ct::Required::new(osis::internals::schema::Retention::default(), Some(60_000))), ..Default::default() };
    db.commit_set(t, ct::REQUIRED, &rules).unwrap();
    db.commit_set(t, osis::DynamicAspectKey::untyped(osis::Ak::new("app:s.0").unwrap()), &s("z")).unwrap();
    assert!(matches!(db.commit_with(|w| w.delete(t)), Err(Error::Invalid(e)) if e.contains("delete") && e.contains("group.0")));
    db.commit_with(|w| w.group(g).remove(osis::Member::Item(t))).unwrap();
    db.commit_with(|w| w.delete(t)).unwrap();
    assert!(!db.has_content(t).unwrap());
}

// spec: none (API surface); notes/api.md Attribution (required retention): `core::REQUIRED` and the engine's `ct::REQUIRED` are
// one aspect in one form, each reading what the other wrote; a `Duration` past what the store counts
// is refused, not stored as something else; `History::FOREVER` stands; a `Keep` keeping nothing
// is written as no history.
#[test]
fn required_rules_are_one_aspect_under_both_keys() {
    use osis::internals::schema::core_types as ct;
    let db = db_at(1);
    let t = thing(&db);
    let ak = |s: &str| osis::Ak::new(s).unwrap();
    let rule = |retention, expires| osis::core::Required { retention, expires };
    let forever = osis::Retention { history: Some(osis::History::FOREVER), ..Default::default() };
    let rules = osis::core::RequiredRules {
        rules: [(ak("app:a.0"), rule(forever, None)), (ak("app:b.0"), rule(osis::Retention::default(), Some(Duration::from_secs(60))))].into(),
        default: Some(rule(osis::Retention::default(), Some(Duration::from_secs(1)))),
        retain_copies: true,
    };
    db.commit_with(|w| w.at(t, osis::core::REQUIRED).set(&rules)).unwrap();
    assert_eq!(db.at(t, osis::core::REQUIRED).get().unwrap(), Some(rules.clone()));
    let engine = db.at(t, ct::REQUIRED).get().unwrap().unwrap();
    assert!(engine.retain);
    assert_eq!(engine.rules[&ak("app:b.0")].expires, Some(60_000));
    assert_eq!(engine.rules[&ak("app:a.0")].history, Some(osis::internals::schema::History::FOREVER));
    assert_eq!(engine.default.and_then(|d| d.expires), Some(1_000));
    db.commit_set(t, ct::REQUIRED, &ct::RequiredRules { retain: false, ..engine }).unwrap();
    assert!(!db.at(t, osis::core::REQUIRED).get().unwrap().unwrap().retain_copies);
    let too_long = |d| osis::core::RequiredRules { rules: [(ak("app:c.0"), d)].into(), default: None, retain_copies: false };
    let held = db.at(t, osis::core::REQUIRED).get().unwrap();
    for bad in [
        rule(osis::Retention::default(), Some(Duration::MAX)),
        rule(osis::Retention { history: Some(osis::History::Keep { until: osis::Time(0), after_replaced: Duration::MAX }), ..Default::default() }, None),
        rule(osis::Retention { history: Some(osis::History::PurgeOnReplace), ..Default::default() }, None),
    ] {
        let mut w = db.write();
        w.at(t, osis::core::REQUIRED).set(&too_long(bad)).unwrap();
        let r = w.commit();
        assert!(matches!(r, Err(Error::Invalid(_))), "{bad:?}: {r:?}");
    }
    assert_eq!(db.at(t, osis::core::REQUIRED).get().unwrap(), held, "nothing written");
    let nothing = osis::Retention { history: Some(osis::History::Keep { until: osis::Time(0), after_replaced: Duration::ZERO }), ..Default::default() };
    db.commit_with(|w| w.at(t, osis::core::REQUIRED).set(&too_long(rule(nothing, None)))).unwrap();
    assert_eq!(db.at(t, osis::core::REQUIRED).get().unwrap().unwrap().rules[&ak("app:c.0")].retention.history, None);
}
