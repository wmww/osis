#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Tracked reads and indexed dispatch (notes/api.md Watching, notes/fast-design.md): cost counted,
//! never timed, on a `Dispatcher::Pump` node so what a commit dispatches runs on this thread.
//! spec: none (API surface, notes/api.md).

use crate::common::TestWrites as _;
use crate::common::*;
use osis::internals::Internals as _;
use osis::internals::costs;
use osis::{CommitFrom, Dispatcher, MemStore, Osis, ReadSet, Scope, Tid, Value, p};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

fn untyped(k: &str) -> osis::DynamicAspectKey {
    osis::DynamicAspectKey::untyped(ak(k))
}

fn pumped_at(seed: u64, clock: &Arc<osis::internals::ManualClock>) -> Osis {
    let mut c = cfg(seed, MemStore::new(), clock);
    c.app.dispatch = Dispatcher::Pump(Arc::new(|| {}));
    osis::internals::create(c).unwrap()
}

fn pumped(seed: u64) -> Osis {
    pumped_at(seed, &clock())
}

fn thing(db: &Osis) -> Tid {
    let mut w = db.write();
    let t = w.create().unwrap();
    w.commit().unwrap();
    db.settle();
    t
}

fn tracked(db: &Osis) -> (ReadSet, Arc<AtomicUsize>, osis::ReadOnly) {
    let n = Arc::new(AtomicUsize::new(0));
    let m = n.clone();
    let set = ReadSet::new(move |_| {
        m.fetch_add(1, Ordering::SeqCst);
    });
    let h = db.tracking(&set);
    (set, n, h)
}

fn count(cs: &[(&str, Duration, u64)], name: &str) -> u64 {
    cs.iter().find(|x| x.0 == name).map_or(0, |x| x.2)
}

fn set(db: &Osis, t: Tid, k: &str, v: i64) {
    db.commit_set(t, untyped(k), &Value::Int(v)).unwrap();
}

fn fired(db: &Osis, n: &AtomicUsize) -> usize {
    db.settle();
    n.swap(0, Ordering::SeqCst)
}

// fast-design Scale: a commit reaches the listeners at its address, whatever else is registered.
#[test]
fn dispatch_counts_matched_listeners_at_n_and_10n() {
    let dispatched = |others: usize| {
        let db = pumped(0);
        let t = thing(&db);
        set(&db, t, "t:a.0", 0);
        let mut subs = Vec::new();
        for i in 0..others {
            let o = thing(&db);
            match i % 4 {
                0 => subs.push(db.at(o, untyped("t:a.0")).on_change(|_, _| {}).unwrap()),
                1 => subs.push(db.on_thing_change(o, |_, _| {}).unwrap()),
                2 => subs.push(db.on_write(&Scope::Thing(o), |_, _| {}).unwrap()),
                _ => subs.push(db.on_grants_change(o, |_, _| {}).unwrap()),
            }
        }
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let _mine = db.at(t, untyped("t:a.0")).on_change(move |_, _| { h.fetch_add(1, Ordering::SeqCst); }).unwrap();
        db.settle();
        hits.store(0, Ordering::SeqCst);
        costs::take();
        set(&db, t, "t:a.0", 1);
        db.settle();
        let cs = costs::take();
        assert_eq!(hits.load(Ordering::SeqCst), 1, "matched listeners only: {cs:?}");
        (count(&cs, "watch: considered"), count(&cs, "watch: dispatched"))
    };
    assert_eq!(dispatched(40), dispatched(400));
}

#[test]
fn a_commit_causes_the_matched_listeners_only() {
    let db = pumped(0);
    let t = thing(&db);
    let mk = |k: &str, n: Arc<AtomicUsize>| db.at(t, untyped(k)).on_change(move |_, _| { n.fetch_add(1, Ordering::SeqCst); }).unwrap();
    let (a, b) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let _s = (mk("t:a.0", a.clone()), mk("t:b.0", b.clone()));
    db.settle();
    a.store(0, Ordering::SeqCst);
    b.store(0, Ordering::SeqCst);
    set(&db, t, "t:a.0", 1);
    db.settle();
    assert_eq!((a.load(Ordering::SeqCst), b.load(Ordering::SeqCst)), (1, 0));
}

// A tracked read then a write at its address fires once; a write elsewhere nothing; an equal
// write nothing.
#[test]
fn tracked_read_fires_once_on_a_write_there() {
    let db = pumped(0);
    let t = thing(&db);
    let (_set, n, h) = tracked(&db);
    assert_eq!(h.at(t, untyped("t:a.0")).get().unwrap(), None);
    set(&db, t, "t:b.0", 1);
    assert_eq!(fired(&db, &n), 0, "a write elsewhere");
    set(&db, t, "t:a.0", 1);
    assert_eq!(fired(&db, &n), 1);
    set(&db, t, "t:a.0", 2);
    assert_eq!(fired(&db, &n), 0, "fires once until read again");
    assert_eq!(h.at(t, untyped("t:a.0")).get().unwrap(), Some(Value::Int(2)));
    db.commit_with(|w| w.at(t, untyped("t:a.0")).set(&Value::Int(2))).unwrap();
    assert_eq!(fired(&db, &n), 0, "an equal write");
    // a value that comes back to what was last read tells nothing: the read's answer is the same
    set(&db, t, "t:a.0", 3);
    set(&db, t, "t:a.0", 2);
    assert_eq!(fired(&db, &n), 0);
}

// The read and its listener are one step: a write queued before the read is not told, a write
// after is, once. The same on a read of an address the set already listens to.
#[test]
fn no_gap_between_read_and_listener() {
    let db = pumped(0);
    let t = thing(&db);
    let (_set, n, h) = tracked(&db);
    set(&db, t, "t:a.0", 1);
    assert_eq!(h.at(t, untyped("t:a.0")).get().unwrap(), Some(Value::Int(1)), "the queued write is read");
    assert_eq!(fired(&db, &n), 0, "its event came before the listener");
    set(&db, t, "t:a.0", 2);
    assert_eq!(h.at(t, untyped("t:a.0")).get().unwrap(), Some(Value::Int(2)));
    assert_eq!(fired(&db, &n), 0, "an existing listener read again skips what the read showed");
    set(&db, t, "t:a.0", 3);
    assert_eq!(fired(&db, &n), 1);
}

#[test]
fn sweep_drops_what_was_not_read() {
    let db = pumped(0);
    let t = thing(&db);
    let (set_, n, h) = tracked(&db);
    let base = db.watches();
    h.at(t, untyped("t:a.0")).get().unwrap();
    h.at(t, untyped("t:b.0")).get().unwrap();
    h.at(t, untyped("t:a.0")).get().unwrap();
    assert_eq!(db.watches(), base + 2, "a read reuses the listener");
    set_.sweep();
    assert_eq!(db.watches(), base + 2, "both read since the last sweep");
    h.at(t, untyped("t:a.0")).get().unwrap();
    set_.sweep();
    assert_eq!(db.watches(), base + 1, "b not read since");
    set(&db, t, "t:b.0", 1);
    assert_eq!(fired(&db, &n), 0, "swept");
    drop(h);
    drop(set_);
    assert_eq!(db.watches(), base, "dropping the set unsubscribes");
}

#[test]
fn tracked_path_reads_their_own_position() {
    let db = pumped(0);
    let t = thing(&db);
    let m = |a, b| Value::Map([(Value::Str("a".into()), Value::Int(a)), (Value::Str("b".into()), Value::Int(b))].into_iter().collect());
    db.commit_set(t, untyped("t:m.0"), &m(1, 1)).unwrap();
    let (_set, n, h) = tracked(&db);
    assert_eq!(h.at(t, untyped("t:m.0")).path(p!["a"]).get::<i64>().unwrap(), Some(1));
    db.commit_set(t, untyped("t:m.0"), &m(1, 2)).unwrap();
    assert_eq!(fired(&db, &n), 0, "the other entry");
    db.commit_set(t, untyped("t:m.0"), &m(2, 2)).unwrap();
    assert_eq!(fired(&db, &n), 1);
}

// `role_on` has no address of its own: it hears every roster and key change, and tells on a
// changed answer only.
#[test]
fn role_on_hears_roles_and_compares() {
    let (a, b, _) = paired();
    let t = a.commit_with(|w| w.create()).unwrap();
    let (_set, n, h) = tracked(&b);
    assert_eq!(h.role_on(t).unwrap(), None);
    a.commit_set(t, untyped("t:a.0"), &Value::Int(1)).unwrap();
    deliver(&a, &b);
    assert_eq!(fired(&b, &n), 1, "the thing's roles arrived");
    assert!(h.role_on(t).unwrap().is_some());
    let other = a.commit_with(|w| w.create()).unwrap();
    deliver(&a, &b);
    b.settle();
    let _ = other;
    assert_eq!(fired(&b, &n), 0, "another thing's roster: the answer here is unchanged");
}

// spec/permissions.md §2 (until), notes/api.md Watching: a grant's `until` passing ends a role
// with no commit (a reader cannot finalize it); a tracked `role_on` and `holders` hear it then (the
// node wakes at the `until`), with no grants watch anywhere, and nothing before it.
#[test]
fn an_until_passing_tells_tracked_role_reads_spec_permissions_2() {
    let c = clock();
    let net = osis::internals::ManualNet::new(c.clone());
    let mut o = cfg(2, MemStore::new(), &c);
    o.app.dispatch = Dispatcher::Pump(Arc::new(|| {}));
    o.app.internals.net = Some(net.clone());
    let bob = osis::internals::create(o).unwrap();
    let alice = osis::internals::create(cfg(1, MemStore::new(), &c)).unwrap();
    deliver(&bob, &alice);
    let g = thing(&alice);
    let until = osis::GrantOpts { until: Some(osis::Time(T0 + 60_000)), ..Default::default() };
    alice.grant(g, bob.me(), osis::Role::Read, until).unwrap();
    deliver(&alice, &bob);
    let ((_s1, roles, h1), (_s2, holders, h2)) = (tracked(&bob), tracked(&bob));
    assert_eq!(h1.role_on(g).unwrap(), Some(osis::Role::Read));
    assert!(h2.holders(g).unwrap().iter().any(|x| x.actor == bob.me()));
    net.advance(30_000);
    assert_eq!((fired(&bob, &roles), fired(&bob, &holders)), (0, 0), "nothing ended yet");
    net.advance(60_000);
    assert_eq!((fired(&bob, &roles), fired(&bob, &holders)), (1, 1), "the until passed");
    assert_eq!(h1.role_on(g).unwrap(), None);
    assert!(!h2.holders(g).unwrap().iter().any(|x| x.actor == bob.me()));
}

// notes/api.md Backlinks: a tracked backlinks page hears a reference to its thing appear, and
// nothing of a reference to another.
#[test]
fn tracked_backlinks_hear_their_thing() {
    let db = pumped(14);
    let (a, x, y) = (thing(&db), thing(&db), thing(&db));
    let (_set, n, h) = tracked(&db);
    assert!(h.backlinks(x, &Default::default()).unwrap().backlinks.is_empty());
    db.commit_with(|w| w.at(a, untyped("t:a.0")).set(&Value::Weak(y))).unwrap();
    assert_eq!(fired(&db, &n), 0);
    db.commit_with(|w| w.at(a, untyped("t:b.0")).set(&Value::Weak(x))).unwrap();
    assert_eq!(fired(&db, &n), 1);
}

// notes/api.md Backlinks: a tracked page of one aspect's backlinks reads that aspect's alone and
// hears nothing of a reference to its thing on another aspect.
#[test]
fn tracked_backlinks_of_an_aspect_hear_that_aspect() {
    let db = pumped(15);
    let (a, x) = (thing(&db), thing(&db));
    let q = osis::BacklinkQuery { aspect: Some(ak("t:b.0")), ..Default::default() };
    let (_set, n, h) = tracked(&db);
    assert!(h.backlinks(x, &q).unwrap().backlinks.is_empty());
    db.commit_with(|w| w.at(a, untyped("t:a.0")).set(&Value::Weak(x))).unwrap();
    assert_eq!(fired(&db, &n), 0, "another aspect's reference");
    assert!(db.backlinks(x, &q).unwrap().backlinks.is_empty());
    db.commit_with(|w| w.at(a, untyped("t:b.0")).set(&Value::Weak(x))).unwrap();
    assert_eq!(fired(&db, &n), 1);
    let page = db.backlinks(x, &q).unwrap();
    assert_eq!(page.backlinks.iter().map(|b| (b.tid, b.ak.as_str())).collect::<Vec<_>>(), vec![(a, "t:b.0")]);
    assert_eq!(db.backlinks(x, &Default::default()).unwrap().backlinks.len(), 2, "every aspect's");
}

// spec/commits.md §7 listing: a tracked page hears a commit at its address (and none elsewhere).
#[test]
fn tracked_listing_hears_the_address() {
    let db = pumped(0);
    let (a, b) = (thing(&db), thing(&db));
    let (_set, n, h) = tracked(&db);
    h.writes(&Scope::Thing(a), &page(CommitFrom::Newest, 8)).unwrap();
    set(&db, b, "t:a.0", 1);
    assert_eq!(fired(&db, &n), 0);
    set(&db, a, "t:a.0", 1);
    assert_eq!(fired(&db, &n), 1);
}

// notes/api.md Tracked reads: a tracked `commit(id)` hears that commit alone: another write at its
// address leaves it be, a purge of it is heard (a quote moves with its message only).
#[test]
fn tracked_commit_hears_its_commit_alone() {
    let db = pumped(0);
    let t = thing(&db);
    typed_any(&db, &["t:k.0"]);
    keep_day(&db, t, &["t:k.0"]);
    let k = kept(&db, &ak("t:k.0"));
    let c = commit_with(&db, |w| w.at(t, k.clone()).set(&Value::Int(1))).stamp.id;
    db.settle();
    let (_set, n, h) = tracked(&db);
    assert!(h.at(t, k.clone()).commit(c).unwrap().is_some());
    db.commit_set(t, k.clone(), &Value::Int(2)).unwrap();
    assert_eq!(fired(&db, &n), 0, "another commit there");
    db.commit_with(|w| w.at(t, k.clone()).purge(osis::Purge::Commit(c))).unwrap();
    assert_eq!(fired(&db, &n), 1, "it, purged");
}

// listing_moved judges only commits a join touched: at n and 10n commits held on the listened
// aspect, one replacing write judges the same few commits, never the whole history.
#[test]
fn listing_moved_counts_touched_commits_at_n_and_10n() {
    let judged = |n: i64| {
        let db = pumped(0);
        let t = thing(&db);
        typed_any(&db, &["t:k.0"]);
        // kept history: the n commits stay held (no compaction snapshot stands for them)
        keep_day(&db, t, &["t:k.0"]);
        let k = kept(&db, &ak("t:k.0"));
        for i in 0..n {
            db.commit_set(t, k.clone(), &Value::Int(i)).unwrap();
        }
        let _s = db.on_write(&Scope::Thing(t), |_, _| {}).unwrap();
        db.settle();
        costs::take();
        db.commit_set(t, k.clone(), &Value::Int(-1)).unwrap();
        let cs = costs::take();
        count(&cs, "listing: commit judged") + count(&cs, "listing: keep bound armed")
    };
    let (small, large) = (judged(20), judged(200));
    assert_eq!(small, large, "commits touched by a join, whatever is held");
}

// a replaced commit with no history kept still leaves its listing and is told (nothing regressed by
// judging only what a join touched).
#[test]
fn replaced_commit_without_history_is_told_leaving() {
    let db = pumped(0);
    let t = thing(&db);
    let c0 = commit_with(&db, |w| w.at(t, untyped("t:a.0")).set(&Value::Int(1))).stamp.id;
    let told: Arc<std::sync::Mutex<Vec<(osis::CommitId, bool)>>> = Arc::default();
    let r = told.clone();
    let _s = db.at(t, untyped("t:a.0")).on_write(move |_, ev| {
        if let osis::CommitEvent::Commit { id, commit } = ev {
            r.lock().unwrap().push((id, commit.is_some()));
        }
    }).unwrap();
    db.commit_set(t, untyped("t:a.0"), &Value::Int(2)).unwrap();
    db.settle();
    assert!(told.lock().unwrap().contains(&(c0, false)), "{:?}", told.lock().unwrap());
}

// One node reading one address twice is what a harness finds through `read_counts`: reads per
// address per pass, starting over at `sweep`; each read is one engine read.
#[test]
fn read_counts_say_what_a_pass_read_twice() {
    let db = pumped(0);
    let t = thing(&db);
    set(&db, t, "t:a.0", 0);
    set(&db, t, "t:b.0", 0);
    let (rs, _n, h) = tracked(&db);
    let (a, b) = (untyped("t:a.0"), untyped("t:b.0"));
    costs::take();
    h.at(t, a.clone()).get().unwrap();
    h.at(t, a.clone()).get().unwrap();
    h.at(t, b.clone()).get().unwrap();
    assert_eq!(count(&costs::take(), "read: engine"), 3);
    rs.sweep();
    let by = |rs: &ReadSet, k: &str| osis::internals::read_counts(rs).into_iter().find(|(a, _)| a.contains(k)).map(|x| x.1);
    assert_eq!((by(&rs, "t:a.0"), by(&rs, "t:b.0")), (Some(2), Some(1)));
    h.at(t, a).get().unwrap();
    rs.sweep();
    assert_eq!((by(&rs, "t:a.0"), by(&rs, "t:b.0")), (Some(1), None), "a second pass starts over");
}
