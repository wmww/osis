//! Tracked reads and indexed dispatch (notes/api.md Watching, notes/fast-design.md): cost counted,
//! never timed, on a `Dispatcher::Pump` node so what a commit dispatches runs on this thread.
//! spec: none (API surface, notes/api.md).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common::TestWrites as _;
use crate::common::*;
use osis::internals::Internals as _;
use osis::internals::node::costs;
use osis::{CommitFrom, Dispatcher, Member, MemStore, Osis, ReadSet, Scope, Tid, Value, p};
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

fn tracked(db: &Osis) -> (ReadSet, Arc<AtomicUsize>, Osis) {
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
        let db = pumped(1);
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
        count(&cs, "watch: dispatched")
    };
    assert_eq!(dispatched(40), dispatched(400));
}

#[test]
fn a_commit_causes_the_matched_listeners_only() {
    let db = pumped(2);
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
    let db = pumped(3);
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
    let db = pumped(4);
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
    let db = pumped(5);
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
    let db = pumped(6);
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

// Reads with no listener of their own are heard by what changes their answer.
#[test]
fn reads_without_a_listener_are_heard() {
    let c = clock();
    let db = pumped_at(7, &c);
    let t = thing(&db);
    let (_set, n, h) = tracked(&db);
    // the names of the aspects: a value change tells nothing, a new aspect does
    set(&db, t, "t:a.0", 1);
    h.aspects(t).unwrap();
    set(&db, t, "t:a.0", 2);
    assert_eq!(fired(&db, &n), 0, "aspects: names unchanged");
    set(&db, t, "t:b.0", 1);
    assert_eq!(fired(&db, &n), 1, "aspects: a new name");
    assert!(h.has_content(t).unwrap());
    db.commit_with(|w| w.delete(t)).unwrap();
    assert_eq!(fired(&db, &n), 1, "has_content: deleted");

    // which groups: a thing added to a group, and through a subgroup
    let (group, sub, item) = (thing(&db), thing(&db), thing(&db));
    assert!(h.groups_of(item).unwrap().item_of.is_empty());
    db.commit_with(|w| w.group(sub).add(Member::Item(item))).unwrap();
    assert_eq!(fired(&db, &n), 1, "groups_of: added");
    h.groups_of(item).unwrap();
    db.commit_with(|w| w.group(group).add(Member::Subgroup(sub))).unwrap();
    assert_eq!(fired(&db, &n), 1, "groups_of: reached through a subgroup");

    // when created and last changed
    let x = thing(&db);
    let before = h.changed(x).unwrap();
    h.created(x).unwrap();
    c.advance(1000);
    set(&db, x, "t:a.0", 1);
    assert_eq!(fired(&db, &n), 1, "changed");
    assert_ne!(h.changed(x).unwrap(), before);

    // undo target: as `on_write(scope)`
    let u = thing(&db);
    assert!(h.undo_target(&Scope::Thing(u)).is_ok());
    assert_eq!(fired(&db, &n), 0);
    keep_day(&db, &["t:k.0"]);
    db.commit_set(u, kept(&db, &ak("t:k.0")), &Value::Int(1)).unwrap();
    assert_eq!(fired(&db, &n), 1, "undo_target");
    db.commit_with(|w| w.at(u, kept(&db, &ak("t:k.0"))).set(&Value::Int(2))).unwrap();
    assert_eq!(fired(&db, &n), 0, "waits for the next read");
}

// `role_on` has no address of its own: it hears every roster and key change, and tells on a
// changed answer only.
#[test]
fn role_on_hears_roles_and_compares() {
    let (a, b, _) = paired();
    let t = a.commit_with(|w| {
        let t = w.create()?;
        w.group(a.me()).add(Member::Item(t))?;
        Ok(t)
    }).unwrap();
    let (_set, n, h) = tracked(&b);
    assert_eq!(h.role_on(t).unwrap(), None);
    a.commit_set(t, untyped("t:a.0"), &Value::Int(1)).unwrap();
    deliver(&a, &b);
    assert_eq!(fired(&b, &n), 1, "the thing's roles arrived");
    assert!(h.role_on(t).unwrap().is_some());
    let other = a.commit_with(|w| { let x = w.create()?; w.group(a.me()).add(Member::Item(x))?; Ok(x) }).unwrap();
    deliver(&a, &b);
    b.settle();
    let _ = other;
    assert_eq!(fired(&b, &n), 0, "another thing's roster: the answer here is unchanged");
}

// `members` is a tracked aspect read: the group's own `group.0`.
#[test]
fn members_is_heard() {
    let db = pumped(8);
    let (g, x) = (thing(&db), thing(&db));
    let (_set, n, h) = tracked(&db);
    assert!(h.members(g).unwrap().is_empty());
    db.commit_with(|w| w.group(g).add(Member::Item(x))).unwrap();
    assert_eq!(fired(&db, &n), 1);
}

// spec/commits.md §7 listing: a tracked page hears a commit at its address (and none elsewhere).
#[test]
fn tracked_listing_hears_the_address() {
    let db = pumped(9);
    let (a, b) = (thing(&db), thing(&db));
    let (_set, n, h) = tracked(&db);
    h.writes(&Scope::Thing(a), &page(CommitFrom::Newest, 8)).unwrap();
    set(&db, b, "t:a.0", 1);
    assert_eq!(fired(&db, &n), 0);
    set(&db, a, "t:a.0", 1);
    assert_eq!(fired(&db, &n), 1);
}

// listing_moved judges only commits a join touched: at n and 10n commits held on the listened
// aspect, one replacing write judges the same few commits, never the whole history.
#[test]
fn listing_moved_counts_touched_commits_at_n_and_10n() {
    let judged = |n: i64| {
        let db = pumped(10);
        let t = thing(&db);
        keep_day(&db, &["t:k.0"]);
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
    let db = pumped(11);
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
