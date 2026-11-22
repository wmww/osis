//! Commit listings and their listeners (notes/api.md Commits): which parts a commit shows (in the
//! read, kept by history until its bound, a purge tombstone, this node's own invalid write), at an
//! aspect, a thing and the things it holds, typed and untyped; pages, `complete`, memory commits; delete for
//! everyone and purge by author.

use osis::internals::Internals as _;
use crate::common::*;
use osis::{Body, CommitEvent, CommitFrom, CommitId, CommitKind, CommitQuery, Error, Osis, Scope, Tid, Value};
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

fn msg() -> osis::Ak {
    ak("t:msg.0")
}

fn key(k: osis::Ak) -> osis::DynamicAspectKey {
    osis::DynamicAspectKey::untyped(k)
}

fn db_at(n: u64) -> Osis {
    crate::common::db(n)
}

/// A thing keeping `msg` and the signal `t:log~0` for good, `t:kept.0` and `t:big.0` a day.
fn thing(db: &Osis) -> Tid {
    thing_keeping(db, &[("t:msg.0", osis::History::FOREVER), ("t:log~0", osis::History::FOREVER), ("t:kept.0", DAY), ("t:big.0", DAY)])
}

/// A write of `x` on `t`'s `msg`, its history kept for good: every one stays listed.
fn say(db: &Osis, t: Tid, x: &str) -> CommitId {
    let mut w = db.write();
    w.at(t, untyped("t:msg.0")).set(&s(x)).unwrap();
    w.commit().unwrap().unwrap().stamp.id
}

/// The bodies of what was written at `(t, k)`, oldest first: content commits and reverts, not the
/// snapshots any writer may add (notes/api.md Delete for everyone).
fn bodies(db: &Osis, t: Tid, k: &osis::Ak) -> Vec<Body<Value>> {
    let q = CommitQuery { kinds: vec![CommitKind::Content, CommitKind::Revert], ..page(CommitFrom::Oldest, 100) };
    db.at(t, key(k.clone())).writes(&q).unwrap().commits.iter().map(|c| part(c, t, k).body).collect()
}

fn watch(db: &Osis, t: Tid, k: osis::Ak) -> (osis::Subscription, Receiver<CommitEvent>) {
    let (tx, rx) = channel();
    let sub = db.at(t, key(k)).on_write(move |_, e| tx.send(e).unwrap()).unwrap();
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

// spec/permissions.md §5.2 (content: the old walk's Acting check, notes/redesign-plan.md, Interim in code), notes/api.md Commits: through
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
    assert_eq!((p.body, p.valid, c.stamp.author, c.kind), (Body::Held(Some(s("one"))), true, db.me(), CommitKind::Content));
    say(&db, t, "two");
    let got = db.at(t, untyped("t:msg.0")).writes(&page(CommitFrom::Newest, 10)).unwrap();
    assert_eq!(got.commits.iter().map(|c| part(c, t, &msg()).body).collect::<Vec<_>>(), vec![Body::Held(Some(s("two"))), Body::Held(Some(s("one")))]);
    assert!(!got.more);
    assert!(got.commits[0].stamp.received.0 > 0);
    for i in 0..osis::internals::COMMIT_PAGE {
        say(&db, t, &format!("m{i}"));
    }
    let got = db.at(t, untyped("t:msg.0")).writes(&page(CommitFrom::Newest, usize::MAX)).unwrap();
    assert_eq!(got.commits.len(), osis::internals::COMMIT_PAGE);
    assert!(got.more);
    let next = db.at(t, untyped("t:msg.0")).writes(&page(CommitFrom::Before(got.commits.last().unwrap().pos()), 1)).unwrap();
    assert_eq!(next.commits.len(), 1);
    // an unknown thing: empty, not an error
    let none = db.at(Tid::from_bytes([7; 15]), untyped("t:msg.0")).writes(&page(CommitFrom::Newest, 5)).unwrap();
    assert!(none.commits.is_empty() && !none.more);
}

// spec/commits.md §7 (Listed parts), §5 Kept while live, spec/sync-compaction.md §1 trigger, notes/api.md
// Commits: a register keeping no history lists only its live write, and once the trigger compacts
// it (no setting keeps it while live) only the snapshot carrying it; one keeping history, declared
// or per write, lists every write until its keep bound, then only the live one again; a signal key
// lists no writes, a value key no fires.
#[test]
fn listed_while_in_read_or_kept_api_commits() {
    let c = clock();
    let db = osis::internals::create(cfg(0, osis::MemStore::new(), &c)).unwrap();
    typed_any(&db, &["t:kept.0"]);
    let t = thing(&db);
    let (plain, decl) = (ak("t:plain.0"), ak("t:kept.0"));
    let held = |v: &str| Body::Held(Some(s(v)));
    for v in ["a", "b", "c"] {
        db.commit_set(t, key(plain.clone()), &s(v)).unwrap();
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
    let listed: Vec<(CommitKind, Body<Value>)> = db.at(t, key(plain.clone())).writes(&all).unwrap().commits.iter().map(|x| (x.kind, part(x, t, &plain).body)).collect();
    assert_eq!(listed, vec![(CommitKind::Snapshot, held("c"))], "the snapshot carrying the live write");
    assert_eq!(bodies(&db, t, &decl), vec![held("a"), held("b"), held("c")], "kept a day");
    assert_eq!(bodies(&db, t, &msg()), vec![held("a"), held("b"), held("c")], "kept for good");
    c.advance(2 * 86_400_000);
    assert_eq!(bodies(&db, t, &decl), vec![held("c")], "past the bound: the live write alone");
    assert_eq!(bodies(&db, t, &msg()).len(), 3, "forever");
    // listing an aspect whose writes keep no history is no error; nor a crossing of kinds
    assert!(db.at(t, key(ak("t:log~0"))).writes(&CommitQuery::default()).unwrap().commits.is_empty());
    assert!(db.at(t, key(plain.clone())).fired(&CommitQuery::default()).unwrap().commits.is_empty());
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
        db.commit_set(p, key(plain.clone()), &s(v)).unwrap();
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
    // its own replaces now cover it: dropped and forgotten (spec/commits.md §5 Own replaces,
    // Forgetting), each a change a listener may hear again, never as listed
    let after = ids(&heard(&db, &rx));
    assert!(after.iter().all(|x| x.0 != a || !x.1), "never listed again: {after:?}");
    assert_eq!(bodies(&db, u, &k), vec![Body::Held(Some(s("b"))), Body::Held(Some(s("d")))]);
}

// spec/commits.md §7 (Listed parts: a purged part is listed while it would be listed unpurged):
// a replaced part past its keep bound has left the listing; a purge naming it then lists nothing
// again, by commit or by author.
#[test]
fn a_purge_lists_no_part_that_had_left_the_listing_spec_commits_7() {
    let c = clock();
    let db = osis::internals::create(cfg(0, osis::MemStore::new(), &c)).unwrap();
    typed_any(&db, &["t:kept.0"]);
    let t = thing(&db);
    let k = ak("t:kept.0");
    let a = commit_with(&db, |w| w.at(t, kept(&db, &k)).set(&s("a"))).stamp.id;
    commit_with(&db, |w| w.at(t, kept(&db, &k)).set(&s("b")));
    c.advance(2 * 86_400_000);
    db.engine(|e| e.tick().unwrap());
    assert_eq!(bodies(&db, t, &k), vec![Body::Held(Some(s("b")))], "a left the listing");
    commit_with(&db, |w| w.at(t, key(k.clone())).purge(osis::Purge::Commit(a)));
    assert_eq!(bodies(&db, t, &k), vec![Body::Held(Some(s("b")))], "purged by commit: a stays unlisted");
    let me = db.me();
    commit_with(&db, |w| w.at(t, key(k.clone())).purge(osis::Purge::Author(me)));
    let got = bodies(&db, t, &k);
    assert!(got.len() == 1 && matches!(got[0], Body::Purged { .. }), "purged by author: b alone listed, as purged: {got:?}");
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
    w.at(a, untyped("t:msg.0")).set(&s("on a")).unwrap();
    w.at(b, n.clone()).set(&Value::Int(5)).unwrap();
    let made = w.commit().unwrap().unwrap();
    let got = db.at(a, untyped("t:msg.0")).writes(&CommitQuery::default()).unwrap().commits;
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
    let odd = commit_with(&db, |w| w.at(b, key(ak("t:n.0"))).set(&s("not an int")));
    let got = db.at(b, n.clone()).writes(&page(CommitFrom::Newest, 1)).unwrap().commits;
    assert_eq!(got[0].stamp.id, odd.stamp.id);
    assert_eq!(got[0].at(b, n.clone()).unwrap().body, Body::Held(None));
    assert_eq!(part(&got[0], b, &ak("t:n.0")).body, Body::Held(Some(s("not an int"))), "the untyped key shows it");
    db.settle();
    assert!(rx.try_iter().any(|d| matches!(d, osis::Diagnostic::Mismatch { .. })), "a mismatch told");
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
    w.at(t, untyped("t:msg.0")).purge(osis::Purge::Commit(a)).unwrap();
    let rq = w.commit().unwrap().unwrap().stamp.id;
    let got = db.at(t, untyped("t:msg.0")).writes(&page(CommitFrom::Oldest, 10)).unwrap();
    assert!(!got.commits.iter().any(|c| c.stamp.id == rq), "the request is not listed");
    let written: Vec<_> = got.commits.iter().filter(|c| c.kind == CommitKind::Content).collect();
    assert_eq!(written.iter().map(|c| c.stamp.id).collect::<Vec<_>>(), vec![a, b]);
    assert_eq!(part(written[0], t, &msg()).body, Body::Purged { by: rq, author: Some(db.me()) });
    assert_eq!(part(written[1], t, &msg()).body, Body::Held(Some(s("next"))));
    assert_eq!(db.at(t, untyped("t:msg.0")).get().unwrap(), Some(s("next")));
    let evs = heard(&db, &rx);
    assert!(evs.iter().any(|e| matches!(e, CommitEvent::Commit { id, commit: Some(c) } if *id == a && matches!(part(c, t, &msg()).body, Body::Purged { .. }))), "{evs:?}");
    // a register's live write purged, no history kept: still listed, as purged
    let x = commit_with(&db, |w| w.at(t, key(ak("t:reg.0"))).set(&s("x")));
    commit_with(&db, |w| w.at(t, key(ak("t:reg.0"))).purge(osis::Purge::Commit(x.stamp.id)));
    assert!(matches!(bodies(&db, t, &ak("t:reg.0"))[..], [Body::Purged { .. }]));
    // an ephemeral write is purged as a durable one, by a durable request of its own
    // (notes/ephemeral.md Principle): beside an ephemeral write it is refused
    let e = commit_with(&db, |w| w.at(t, key(ak("t:x+.0"))).set(&s("eph")));
    assert_eq!(db.at(t, key(ak("t:x+.0"))).get().unwrap(), Some(s("eph")));
    commit_with(&db, |w| w.at(t, key(ak("t:x+.0"))).purge(osis::Purge::Commit(e.stamp.id)));
    assert_eq!(db.at(t, key(ak("t:x+.0"))).get().unwrap(), None);
    let mut w = db.write();
    w.at(t, key(ak("t:x+.0"))).set(&s("again")).unwrap();
    w.at(t, key(ak("t:x+.0"))).purge(osis::Purge::All).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(m)) if m.contains("a purge is not")), "a write is one commit");
    // `Purge::All` of an ephemeral aspect: it reads as absent, as a durable one removed
    commit_with(&db, |w| w.at(t, key(ak("t:x+.0"))).set(&s("again")));
    commit_with(&db, |w| w.at(t, key(ak("t:x+.0"))).purge(osis::Purge::All));
    assert_eq!(db.at(t, key(ak("t:x+.0"))).get().unwrap(), None);
    commit_with(&db, |w| w.at(t, key(ak("t:m+.0"))).set(&osis::Value::Map(osis_base::ValueMap::from([(s("k"), s("v"))]))));
    commit_with(&db, |w| w.at(t, key(ak("t:m+.0"))).purge(osis::Purge::All));
    assert_eq!(db.at(t, key(ak("t:m+.0"))).get().unwrap(), None);
}

// spec/commits.md §5 Forgetting (a forgotten commit's name), Purge: a write with no history kept,
// compacted and its commit forgotten (header and ID gone), is still purged by its ID: the snapshot
// carrying it holds it value-less.
#[test]
fn purge_commit_reaches_a_forgotten_write_spec_commits_5() {
    let db = db_at(0);
    let t = thing(&db);
    let k = ak("t:reg.0");
    let x = commit_with(&db, |w| w.at(t, key(k.clone())).set(&s("secret"))).stamp.id;
    db.engine(|e| {
        let s = e.snapshot(&t, &k).unwrap().unwrap();
        let on: Vec<_> = e.commit_ids().into_iter().filter(|c| *c != s && e.header(c).is_some_and(|h| h.aspects.iter().any(|a| a.tid == t && a.ak == k))).collect();
        for c in on {
            e.drop_body(&c, &t, &k).unwrap();
        }
        let due: Vec<_> = e.commit_ids().into_iter().filter(|c| e.forgettable(c).unwrap()).collect();
        assert!(!due.is_empty());
        e.forget_commits(&due).unwrap();
    });
    assert_eq!(db.at(t, key(k.clone())).get().unwrap(), Some(s("secret")));
    commit_with(&db, |w| w.at(t, key(k.clone())).purge(osis::Purge::Commit(x)));
    assert_eq!(db.at(t, key(k.clone())).get().unwrap(), None);
}

// spec/data-model.md §6 (holds the root link), notes/api.md Commits: a page is bounded in the bytes of its values, a link's once materialized, so
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
        commit_with(&db, |w| w.at(t, key(k.clone())).set(&Value::Bytes(vec![b; n])));
    };
    put(2 << 20, 1);
    put(2 << 20, 2);
    put(2 << 20, 3);
    let list = |from| db.at(t, key(k.clone())).writes(&page(from, 10)).unwrap();
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

// spec/commits.md §5 (fixed retention; which carries no `expires`): a setting with an
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
    w.at(t, untyped("t:msg.0")).purge(osis::Purge::Commit(a)).unwrap();
    let rq = w.commit().unwrap().unwrap().stamp.id;
    let got = db.at(t, untyped("t:msg.0")).writes(&page(CommitFrom::Oldest, 1)).unwrap();
    assert_eq!(part(&got.commits[0], t, &msg()).body, Body::Purged { by: rq, author: Some(db.me()) });
    // beside a write of the thing, a request goes under it and takes its expiry: one commit
    let mut w = db.write();
    w.at(t, untyped("t:msg.0")).set(&s("y")).unwrap();
    let b = w.commit().unwrap().unwrap().stamp.id;
    let mut w = db.write();
    w.at(t, untyped("t:other.0")).set(&s("z")).unwrap();
    w.at(t, untyped("t:msg.0")).purge(osis::Purge::Commit(b)).unwrap();
    let done = w.commit().unwrap().unwrap();
    assert!(done.parts().all(|(_, ak, _)| ak.as_str() != "purge.0"), "no purge.0 write: {done:?}");
    let got = db.at(t, untyped("t:msg.0")).writes(&page(CommitFrom::Oldest, 8)).unwrap();
    assert!(got.commits.iter().any(|k| k.stamp.id == b && part(k, t, &msg()).body == Body::Purged { by: done.stamp.id, author: Some(db.me()) }), "{got:?}");
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
        history_holds_targets: true,
    };
    db.commit_with(|w| w.at(t, osis::core::RETENTION).set(&rules)).unwrap();
    assert_eq!(db.at(t, osis::core::RETENTION).get().unwrap(), Some(rules.clone()));
    let engine = db.at(t, ct::RETENTION).get().unwrap().unwrap();
    assert!(engine.retain && engine.history_holds_targets);
    assert_eq!(engine.rules[&ak("app:b.0")].expires, Some(60_000));
    assert_eq!(engine.rules[&ak("app:a.0")].history, Some(osis::internals::schema::History::FOREVER));
    assert_eq!(engine.default.and_then(|d| d.expires), Some(1_000));
    db.commit_set(t, ct::RETENTION, &ct::RetentionSetting { retain: false, ..engine }).unwrap();
    assert!(!db.at(t, osis::core::RETENTION).get().unwrap().unwrap().retain_copies);
    let too_long = |d| osis::core::RetentionSetting { rules: [(ak("app:c.0"), d)].into(), default: None, retain_copies: false, history_holds_targets: false };
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
// places the request there (`purge.0`), never only under another thing's sync IDs.
#[test]
fn purge_goes_under_its_thing_and_reaches_what_it_names_spec_commits_5() {
    let db = db(0);
    let t = thing(&db);
    let a = say(&db, t, "secret");
    for what in [osis::Purge::Commit(a), osis::Purge::Author(db.me())] {
        let mut w = db.write();
        w.at(t, key(ak("t:other.0"))).set(&s("z")).unwrap();
        w.at(t, untyped("t:msg.0")).purge(what).unwrap();
        w.expires(osis::Expiry::In(std::time::Duration::from_secs(600)));
        assert!(matches!(w.commit(), Err(Error::Invalid(_))), "an expiring commit cannot reach a permanent delta");
    }
    assert_eq!(bodies(&db, t, &msg()), vec![Body::Held(Some(s("secret")))]);
    commit_with(&db, |w| w.at(t, key(ak("t:other.0"))).set(&s("z")));
    let u = thing(&db);
    let mut w = db.write();
    w.at(t, key(ak("t:other.0"))).set(&s("z")).unwrap();
    w.at(u, key(ak("t:other.0"))).set(&s("q")).unwrap();
    w.at(t, untyped("t:msg.0")).purge(osis::Purge::Commit(a)).unwrap();
    let done = w.commit().unwrap().unwrap();
    assert!(done.parts().any(|(x, _, _)| x == t), "a delta on the purged thing: {done:?}");
    assert!(matches!(bodies(&db, t, &msg())[..], [Body::Purged { .. }]));
}

// spec/sync.md §2 (Work in proportion to change): one more write to an aspect keeping its
// history, for good (`t:msg.0`) or a day after replaced (`t:kept.0`, each body dated), re-derives
// the sync facts and fates and dates of the bodies it replaces, not of every body kept there: the
// same work after 8 and after 80 kept writes.
#[test]
fn a_kept_write_rederives_only_what_it_replaces_spec_sync_2() {
    let per_write = |aspect: &str, n: usize| {
        let db = db(0);
        let t = thing(&db);
        let put = |x: &str| {
            let mut w = db.write();
            w.at(t, untyped(aspect)).set(&s(x)).unwrap();
            w.commit().unwrap();
        };
        for i in 0..n {
            put(&format!("m{i}"));
        }
        db.settle();
        osis::internals::costs::take();
        put("last");
        db.settle();
        let c = osis::internals::costs::take();
        let n_of = |name: &str| c.iter().filter(|x| x.0.starts_with(name)).map(|x| x.2).sum::<u64>();
        [n_of("sync: read facts <- "), n_of("sync: held fate <- "), n_of("replaced at"), n_of("covered: join")]
    };
    for aspect in ["t:msg.0", "t:kept.0"] {
        let (small, big) = (per_write(aspect, 8), per_write(aspect, 80));
        assert_eq!(small, big, "{aspect}: facts, fates refreshed, bodies dated and joins judged by one write after 8 kept writes, then after 80");
    }
}
