//! Commit listings and their listeners (notes/api.md Commits): which parts a commit shows (in the
//! read, kept by history until its bound, a purge tombstone, this node's own invalid write), at an
//! aspect, a thing and a group, typed and untyped; pages, `complete`, memory commits; delete for
//! everyone and purge by author.

use crate::common::TestWrites as _;
use osis::internals::Internals as _;
use crate::common::*;
use osis::{Body, CommitEvent, CommitFrom, CommitId, CommitKind, CommitQuery, Error, Osis, Scope, Tid, Value};
use std::collections::BTreeSet;
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

/// A thing keeping `msg` and the signal `t:log~0` for good, `t:kept.0` and `t:big.0` a day.
fn thing(db: &Osis) -> Tid {
    let x = crate::common::setting(&[("t:msg.0", osis::History::FOREVER), ("t:log~0", osis::History::FOREVER), ("t:kept.0", crate::common::DAY), ("t:big.0", crate::common::DAY)]);
    db.commit_with(|w| {
        let t = w.create()?;
        w.at(t, osis::core::RETENTION).set(&x)?;
        Ok(t)
    })
    .unwrap()
}

/// A write of `x` on `t`'s `msg`, its history kept for good: every one stays listed.
fn say(db: &Osis, t: Tid, x: &str) -> CommitId {
    let mut w = db.write();
    w.at(t, untyped(msg())).set(&s(x)).unwrap();
    w.commit().unwrap().unwrap().stamp.id
}

/// The bodies of what was written at `(t, k)`, oldest first: content commits and reverts, not the
/// snapshots any writer may add (notes/api.md Delete for everyone).
fn bodies(db: &Osis, t: Tid, k: &osis::Ak) -> Vec<Body<Value>> {
    let q = CommitQuery { kinds: vec![CommitKind::Content, CommitKind::Revert], ..page(CommitFrom::Oldest, 100) };
    db.at(t, untyped(k.clone())).writes(&q).unwrap().commits.iter().map(|c| part(c, t, k).body).collect()
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
    let db = db(0);
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

// spec/commits.md §7 (Listed parts), §5 Kept while live, spec/sync-compaction.md §1 trigger, notes/api.md
// Commits: a register keeping no history lists only its live write, and once the trigger compacts
// it (no setting keeps it while live) only the snapshot carrying it; one keeping history, declared
// or per write, lists every write until its keep bound, then only the live one again; a signal key
// lists no writes, a value key no fires.
#[test]
#[ignore = "sync rewrite"]
fn listed_while_in_read_or_kept_api_commits() {
    let c = clock();
    let db = osis::internals::create(cfg(0, osis::MemStore::new(), &c)).unwrap();
    typed_any(&db, &["t:kept.0"]);
    let t = thing(&db);
    let (plain, decl) = (ak("t:plain.0"), ak("t:kept.0"));
    let held = |v: &str| Body::Held(Some(s(v)));
    for v in ["a", "b", "c"] {
        db.commit_set(t, untyped(plain.clone()), &s(v)).unwrap();
        if v == "a" {
            assert_eq!(bodies(&db, t, &plain), vec![held("a")], "no history: the live write alone");
        }
        db.commit_set(t, kept(&db, &decl), &s(v)).unwrap();
        say(&db, t, v);
    }
    // the trigger compacted `plain` (three own whole replaces: the first covered by the other two,
    // they by the snapshot): its live value is listed as the snapshot's
    assert_eq!(bodies(&db, t, &plain), vec![], "no history: the live write compacted away");
    let all = CommitQuery { kinds: vec![CommitKind::Content, CommitKind::Revert, CommitKind::Snapshot], ..page(CommitFrom::Oldest, 100) };
    let listed: Vec<(CommitKind, Body<Value>)> = db.at(t, untyped(plain.clone())).writes(&all).unwrap().commits.iter().map(|x| (x.kind, part(x, t, &plain).body)).collect();
    assert_eq!(listed, vec![(CommitKind::Snapshot, held("c"))], "the snapshot carrying the live write");
    assert_eq!(bodies(&db, t, &decl), vec![held("a"), held("b"), held("c")], "kept a day");
    assert_eq!(bodies(&db, t, &msg()), vec![held("a"), held("b"), held("c")], "kept for good");
    c.advance(2 * 86_400_000);
    assert_eq!(bodies(&db, t, &decl), vec![held("c")], "past the bound: the live write alone");
    assert_eq!(bodies(&db, t, &msg()).len(), 3, "forever");
    // listing an aspect whose writes keep no history is no error; nor a crossing of kinds
    assert!(db.at(t, untyped(ak("t:log~0"))).writes(&CommitQuery::default()).unwrap().commits.is_empty());
    assert!(db.at(t, untyped(plain.clone())).fired(&CommitQuery::default()).unwrap().commits.is_empty());
}

// spec/commits.md §7 (Listed parts), notes/api.md Commits (listeners): a replaced part leaving
// the listing at its keep bound is told, to a listener added before its replacement and to one
// added after, once; the kept aspect has one timer whoever listens, and an aspect whose writes keep
// no history has none.
#[test]
fn kept_part_is_told_leaving_at_its_bound_api_commits() {
    let c = clock();
    let db = osis::internals::create(cfg(0, osis::MemStore::new(), &c)).unwrap();
    typed_any(&db, &["t:kept.0"]);
    let t = thing(&db);
    let (k, plain) = (ak("t:kept.0"), ak("t:plain.0"));
    let timer = || db.engine(|e| e.next_timer().unwrap());
    let x = commit_with(&db, |w| w.at(t, kept(&db, &k)).set(&s("x"))).stamp.id;
    commit_with(&db, |w| w.at(t, kept(&db, &k)).set(&s("y")));
    let first = timer();
    assert!(first.is_some(), "the kept aspect's timer, listened or not");
    let p = thing(&db);
    let (_p, prx) = watch(&db, p, plain.clone());
    for v in ["x", "y"] {
        db.commit_set(p, untyped(plain.clone()), &s(v)).unwrap();
    }
    assert_eq!(timer(), first, "no history kept: no timer of its own");
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
    let db = db(0);
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
    let db = db(0);
    db.register_schema("n.osis", "revision 1;\naspect t:n.0: int;\n").unwrap();
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
    let db = db(0);
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
    commit_with(&db, |w| w.at(t, log.clone()).fire(&s("ping")));
    assert_eq!(ids(&heard(&db, &rx)), vec![(mine, true)], "its commit, nothing beside, no signal");
    assert_eq!(ids(&heard(&db, &grx)), vec![(mine, true)], "a member's commit");
    assert_eq!(db.at(t, log).fired(&CommitQuery::default()).unwrap().commits.len(), 1, "the signal lists at its key");
}

// spec/commits.md §5, notes/api.md Commits: delete for everyone: one commit's body goes for good
// and it stays listed as a tombstone; what the state reads does not change for a dead write; the
// request is not listed at the aspect it purges (a writer may add a snapshot there); the listener
// tells it.
#[test]
fn purge_commit_is_delete_for_everyone_spec_commits_5() {
    let db = db(0);
    let t = thing(&db);
    let a = say(&db, t, "secret");
    let b = say(&db, t, "next");
    let (_sub, rx) = watch(&db, t, msg());
    let mut w = db.write();
    w.at(t, untyped(msg())).purge(osis::Purge::Commit(a)).unwrap();
    let rq = w.commit().unwrap().unwrap().stamp.id;
    let got = db.at(t, untyped(msg())).writes(&page(CommitFrom::Oldest, 10)).unwrap();
    assert!(!got.commits.iter().any(|c| c.stamp.id == rq), "the request is not listed");
    let written: Vec<_> = got.commits.iter().filter(|c| c.kind == CommitKind::Content).collect();
    assert_eq!(written.iter().map(|c| c.stamp.id).collect::<Vec<_>>(), vec![a, b]);
    assert_eq!(part(written[0], t, &msg()).body, Body::Purged { by: rq, actor: Some(db.me()) });
    assert_eq!(part(written[1], t, &msg()).body, Body::Held(Some(s("next"))));
    assert_eq!(db.at(t, untyped(msg())).get().unwrap(), Some(s("next")));
    let evs = heard(&db, &rx);
    assert!(evs.iter().any(|e| matches!(e, CommitEvent::Commit { id, commit: Some(c) } if *id == a && matches!(part(c, t, &msg()).body, Body::Purged { .. }))), "{evs:?}");
    // a register's live write purged, no history kept: still listed, as purged
    let x = commit_with(&db, |w| w.at(t, untyped(ak("t:reg.0"))).set(&s("x")));
    commit_with(&db, |w| w.at(t, untyped(ak("t:reg.0"))).purge(osis::Purge::Commit(x.stamp.id)));
    assert!(matches!(bodies(&db, t, &ak("t:reg.0"))[..], [Body::Purged { .. }]));
    // an ephemeral write is purged as a durable one, by a durable request of its own
    // (notes/ephemeral.md Principle): beside an ephemeral write it is refused
    let e = commit_with(&db, |w| w.at(t, untyped(ak("t:x+.0"))).set(&s("eph")));
    assert_eq!(db.at(t, untyped(ak("t:x+.0"))).get().unwrap(), Some(s("eph")));
    commit_with(&db, |w| w.at(t, untyped(ak("t:x+.0"))).purge(osis::Purge::Commit(e.stamp.id)));
    assert_eq!(db.at(t, untyped(ak("t:x+.0"))).get().unwrap(), None);
    let mut w = db.write();
    w.at(t, untyped(ak("t:x+.0"))).set(&s("again")).unwrap();
    w.at(t, untyped(ak("t:x+.0"))).purge(osis::Purge::All).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(m)) if m.contains("a purge is not")), "a write is one commit");
    // `Purge::All` of an ephemeral aspect: it reads as absent, as a durable one removed
    commit_with(&db, |w| w.at(t, untyped(ak("t:x+.0"))).set(&s("again")));
    commit_with(&db, |w| w.at(t, untyped(ak("t:x+.0"))).purge(osis::Purge::All));
    assert_eq!(db.at(t, untyped(ak("t:x+.0"))).get().unwrap(), None);
    commit_with(&db, |w| w.at(t, untyped(ak("t:m+.0"))).set(&osis::Value::Map(osis_base::ValueMap::from([(s("k"), s("v"))]))));
    commit_with(&db, |w| w.at(t, untyped(ak("t:m+.0"))).purge(osis::Purge::All));
    assert_eq!(db.at(t, untyped(ak("t:m+.0"))).get().unwrap(), None);
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
        commit_with(&db, |w| w.at(t, untyped(k.clone())).set(&Value::Bytes(vec![b; n])));
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

// spec/commits.md §5 (fixed retention, a request alone carries no `expires`): a setting with an
// expiry on every aspect reaches no `purge.0`, so delete for everyone still works in a
// disappearing chat; a request beside a write of the thing goes under that write, with its expiry
// (an edit purging old text).
#[test]
fn purge_takes_no_setting_expiry_spec_commits_5() {
    use osis::internals::schema::core_types as ct;
    let db = db(0);
    let t = thing(&db);
    let a = say(&db, t, "x");
    let rules = ct::RetentionSetting { default: Some(ct::RetentionEntry { expires: Some(60_000), ..Default::default() }), ..Default::default() };
    db.commit_set(t, ct::RETENTION, &rules).unwrap();
    let mut w = db.write();
    w.at(t, osis::DynamicAspectKey::untyped(msg())).purge(osis::Purge::Commit(a)).unwrap();
    let rq = w.commit().unwrap().unwrap().stamp.id;
    let got = db.at(t, untyped(msg())).writes(&page(CommitFrom::Oldest, 1)).unwrap();
    assert_eq!(part(&got.commits[0], t, &msg()).body, Body::Purged { by: rq, actor: Some(db.me()) });
    // beside a write of the thing, a request goes under it and takes its expiry: one commit
    let mut w = db.write();
    w.at(t, osis::DynamicAspectKey::untyped(msg())).set(&s("y")).unwrap();
    let b = w.commit().unwrap().unwrap().stamp.id;
    let mut w = db.write();
    w.at(t, osis::DynamicAspectKey::untyped(ak("t:other.0"))).set(&s("z")).unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(msg())).purge(osis::Purge::Commit(b)).unwrap();
    let done = w.commit().unwrap().unwrap();
    assert!(done.parts().all(|(_, ak, _)| ak.as_str() != "purge.0"), "no purge.0 write: {done:?}");
    let got = db.at(t, untyped(msg())).writes(&page(CommitFrom::Oldest, 8)).unwrap();
    assert!(got.commits.iter().any(|k| k.stamp.id == b && part(k, t, &msg()).body == Body::Purged { by: done.stamp.id, actor: Some(db.me()) }), "{got:?}");
}

// spec/commits.md §5 (a writer does not undo `retention^.0`), notes/api.md `has_content`: a setting is no content: a delete leaves it in force and the thing reads deleted; undoing the creation likewise
#[test]
fn setting_is_no_content_spec_commits_5() {
    use osis::internals::schema::core_types as ct;
    let db = db(0);
    let rules = ct::RetentionSetting { retain: true, ..Default::default() };
    let t = thing(&db);
    say(&db, t, "x");
    db.commit_set(t, ct::RETENTION, &rules).unwrap();
    let mut w = db.write();
    w.delete(t).unwrap();
    w.commit().unwrap();
    assert!(!db.has_content(t).unwrap(), "deleted");
    assert_eq!(db.at(t, ct::RETENTION).get().unwrap(), Some(rules.clone()), "still in force");
    let mut w = db.write();
    let u = w.create().unwrap();
    w.at(u, osis::DynamicAspectKey::untyped(msg())).set(&s("x")).unwrap();
    w.at(u, ct::RETENTION).set(&rules).unwrap();
    w.commit().unwrap();
    db.undo(&osis::Scope::Thing(u)).unwrap();
    assert!(!db.has_content(u).unwrap(), "undone");
    assert_eq!(db.at(u, ct::RETENTION).get().unwrap(), Some(rules));
}

// spec/commits.md §5, §6: a writer fills each delta's expiry from its thing's setting, a delete's
// resets too, so a delete of a thing whose aspects (or groups) get different expiries is several
// commits' work: refused, telling the app to do the rest first, and then the delete goes through.
#[test]
fn delete_under_setting_expiries_says_what_to_do_spec_commits_6() {
    use osis::internals::schema::core_types as ct;
    let db = db_at(50);
    let t = db.commit_with(|w| w.create()).unwrap();
    let rules = ct::RetentionSetting { rules: [(osis::Ak::new("app:m.0").unwrap(), ct::RetentionEntry { expires: Some(60_000), ..Default::default() })].into(), ..Default::default() };
    db.commit_set(t, ct::RETENTION, &rules).unwrap();
    let (m, plain) = (osis::DynamicAspectKey::untyped(osis::Ak::new("app:m.0").unwrap()), osis::DynamicAspectKey::untyped(osis::Ak::new("app:s.0").unwrap()));
    db.commit_set(t, m.clone(), &s("x")).unwrap();
    db.commit_set(t, plain.clone(), &s("y")).unwrap();
    assert!(matches!(db.commit_with(|w| w.delete(t)), Err(Error::Invalid(e)) if e.contains("delete") && e.contains("first") && !e.contains("separate")));
    assert!(db.has_content(t).unwrap(), "nothing applied");
    db.commit_with(|w| w.at(t, m).remove()).unwrap();
    db.commit_with(|w| w.delete(t)).unwrap();
    assert!(!db.has_content(t).unwrap());
    // the group's removal goes first likewise, when the thing's own writes expire
    let db = db_at(52);
    let g = thing(&db);
    let t = thing(&db);
    db.commit_set(g, osis::DynamicAspectKey::untyped(osis::Ak::new("app:s.0").unwrap()), &s("y")).unwrap();
    db.commit_set(t, osis::DynamicAspectKey::untyped(osis::Ak::new("app:s.0").unwrap()), &s("y")).unwrap();
    db.commit_with(|w| w.group(g).add(osis::Member::Item(t))).unwrap();
    let rules = ct::RetentionSetting { default: Some(ct::RetentionEntry { expires: Some(60_000), ..Default::default() }), ..Default::default() };
    db.commit_set(t, ct::RETENTION, &rules).unwrap();
    db.commit_set(t, osis::DynamicAspectKey::untyped(osis::Ak::new("app:s.0").unwrap()), &s("z")).unwrap();
    assert!(matches!(db.commit_with(|w| w.delete(t)), Err(Error::Invalid(e)) if e.contains("delete") && e.contains("group.0")));
    db.commit_with(|w| w.group(g).remove(osis::Member::Item(t))).unwrap();
    db.commit_with(|w| w.delete(t)).unwrap();
    assert!(!db.has_content(t).unwrap());
}

// spec: none (API surface); notes/api.md (the setting): `core::RETENTION` and the engine's `ct::RETENTION` are
// one aspect in one form, each reading what the other wrote; a `Duration` past what the store counts
// is refused, not stored as something else; `History::FOREVER` stands; a `Keep` keeping nothing
// is written as no history.
#[test]
fn settings_are_one_aspect_under_both_keys() {
    use osis::internals::schema::core_types as ct;
    let db = db_at(1);
    let t = thing(&db);
    let ak = |s: &str| osis::Ak::new(s).unwrap();
    let rule = |history, expires| osis::core::RetentionEntry { history, expires, refuse_replace: false };
    let rules = osis::core::RetentionSetting {
        rules: [(ak("app:a.0"), rule(Some(osis::History::FOREVER), None)), (ak("app:b.0"), rule(None, Some(Duration::from_secs(60))))].into(),
        default: Some(rule(None, Some(Duration::from_secs(1)))),
        retain_copies: true,
    };
    db.commit_with(|w| w.at(t, osis::core::RETENTION).set(&rules)).unwrap();
    assert_eq!(db.at(t, osis::core::RETENTION).get().unwrap(), Some(rules.clone()));
    let engine = db.at(t, ct::RETENTION).get().unwrap().unwrap();
    assert!(engine.retain);
    assert_eq!(engine.rules[&ak("app:b.0")].expires, Some(60_000));
    assert_eq!(engine.rules[&ak("app:a.0")].history, Some(osis::internals::schema::History::FOREVER));
    assert_eq!(engine.default.and_then(|d| d.expires), Some(1_000));
    db.commit_set(t, ct::RETENTION, &ct::RetentionSetting { retain: false, ..engine }).unwrap();
    assert!(!db.at(t, osis::core::RETENTION).get().unwrap().unwrap().retain_copies);
    let too_long = |d| osis::core::RetentionSetting { rules: [(ak("app:c.0"), d)].into(), default: None, retain_copies: false };
    let held = db.at(t, osis::core::RETENTION).get().unwrap();
    for bad in [rule(None, Some(Duration::MAX)), rule(Some(osis::History::Keep { until: osis::Time(0), after_replaced: Duration::MAX }), None)] {
        let mut w = db.write();
        w.at(t, osis::core::RETENTION).set(&too_long(bad)).unwrap();
        let r = w.commit();
        assert!(matches!(r, Err(Error::Invalid(_))), "{bad:?}: {r:?}");
    }
    assert_eq!(db.at(t, osis::core::RETENTION).get().unwrap(), held, "nothing written");
    let nothing = Some(osis::History::Keep { until: osis::Time(0), after_replaced: Duration::ZERO });
    db.commit_with(|w| w.at(t, osis::core::RETENTION).set(&too_long(rule(nothing, None)))).unwrap();
    assert_eq!(db.at(t, osis::core::RETENTION).get().unwrap().unwrap().rules[&ak("app:c.0")].history, None);
}

// spec/commits.md §5 Purge: a request rides a delta on its thing. In a commit that expires it
// reaches only what expires no later, so a writer refuses one naming more, never writing a purge
// that drops less than it says; and a write that turns out to write nothing on the thing still
// places the request there (`purge.0`), never only under another thing's labels.
#[test]
fn purge_goes_under_its_thing_and_reaches_what_it_names_spec_commits_5() {
    let db = db(0);
    let t = thing(&db);
    let a = say(&db, t, "secret");
    for what in [osis::Purge::Commit(a), osis::Purge::Author(db.me())] {
        let mut w = db.write();
        w.at(t, untyped(ak("t:other.0"))).set(&s("z")).unwrap();
        w.at(t, untyped(msg())).purge(what).unwrap();
        w.expires(osis::Expiry::In(std::time::Duration::from_secs(600)));
        assert!(matches!(w.commit(), Err(Error::Invalid(_))), "an expiring commit cannot reach a permanent delta");
    }
    assert_eq!(bodies(&db, t, &msg()), vec![Body::Held(Some(s("secret")))]);
    commit_with(&db, |w| w.at(t, untyped(ak("t:other.0"))).set(&s("z")));
    let u = thing(&db);
    let mut w = db.write();
    w.at(t, untyped(ak("t:other.0"))).set(&s("z")).unwrap();
    w.at(u, untyped(ak("t:other.0"))).set(&s("q")).unwrap();
    w.at(t, untyped(msg())).purge(osis::Purge::Commit(a)).unwrap();
    let done = w.commit().unwrap().unwrap();
    assert!(done.parts().any(|(x, _, _)| x == t), "a delta on the purged thing: {done:?}");
    assert!(matches!(bodies(&db, t, &msg())[..], [Body::Purged { .. }]));
}

// notes/api.md `delete`, spec/crdt.md §5.5: a delete removes the thing from every group it may
// write alike, its adds held and those held as a commit header only. N is an item of G and of H;
// B holds H's add as a header only (its part not received yet) when it deletes N: once synced, N
// is in neither group, at A as at B, and H's late part does not bring it back.
#[test]
fn delete_unlists_an_add_not_received_spec_crdt_5_5() {
    let (a, b, _) = paired();
    let (g, h, n) = a.commit_with(|w| Ok((w.create()?, w.create()?, w.create()?))).unwrap();
    a.commit_set(n, untyped(msg()), &s("x")).unwrap();
    a.commit_with(|w| w.group(g).add(osis::Member::Item(n))).unwrap();
    deliver(&a, &b);
    let mut w = a.write();
    w.group(h).add(osis::Member::Item(n)).unwrap();
    let add_h = w.commit().unwrap().unwrap().stamp.id;
    let pk = a.engine(|e| e.commit_ids().into_iter().find(|id| CommitId::from(*id) == add_h).and_then(|id| e.package(&id).unwrap())).unwrap();
    let blob = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    let header_only = osis_commit::rewrite(&blob, |ai| blob.header.aspects[ai].tid == h).encode();
    b.engine(|e| e.ingest(&header_only, pk.blobs.clone()).unwrap());
    assert_eq!((b.groups_of(n).unwrap().item_of, a.groups_of(n).unwrap().item_of.len()), (vec![g], 2), "B holds H's add of N as a header only");
    b.commit_with(|w| w.delete(n)).unwrap();
    for _ in 0..2 {
        deliver(&b, &a);
        deliver(&a, &b);
        for (who, d) in [("A", &a), ("B", &b)] {
            assert_eq!(d.groups_of(n).unwrap().item_of, Vec::<Tid>::new(), "N listed at {who}");
            assert!(!d.has_content(n).unwrap(), "N deleted at {who}");
        }
    }
}

// spec/requirements.md (Data model: removing drops only what the remover had seen), spec/crdt.md
// §5.5: an add the deleting node never heard of, not even its commit header, survives the delete,
// in a group it lists the thing in too. N is an item of G at both; A removes it from G and adds
// it again, and adds it to H, none of which B has received when it deletes N later: once synced,
// N's content is deleted and it is still listed in G and H, at A as at B.
#[test]
fn delete_keeps_an_add_never_seen_spec_crdt_5_5() {
    let (a, b, c) = paired();
    let (g, h, n) = a.commit_with(|w| Ok((w.create()?, w.create()?, w.create()?))).unwrap();
    a.commit_set(n, untyped(msg()), &s("x")).unwrap();
    a.commit_with(|w| w.group(g).add(osis::Member::Item(n))).unwrap();
    deliver(&a, &b);
    a.commit_with(|w| w.group(g).remove(osis::Member::Item(n))).unwrap();
    a.commit_with(|w| w.group(g).add(osis::Member::Item(n))).unwrap();
    a.commit_with(|w| w.group(h).add(osis::Member::Item(n))).unwrap();
    assert_eq!(b.groups_of(n).unwrap().item_of, vec![g], "B has not heard of A's adds");
    c.advance(1000);
    b.commit_with(|w| w.delete(n)).unwrap();
    let both = BTreeSet::from([g, h]);
    for _ in 0..2 {
        deliver(&b, &a);
        deliver(&a, &b);
        for (who, d) in [("A", &a), ("B", &b)] {
            assert_eq!(d.groups_of(n).unwrap().item_of.into_iter().collect::<BTreeSet<_>>(), both, "N listed in G and H at {who}");
            assert!(!d.has_content(n).unwrap(), "N deleted at {who}");
        }
    }
}
