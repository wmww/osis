//! Replacing a signal's fire through the API (notes/api.md Signals; spec/commits.md §5 Signals):
//! `replace` writes an edit, listings, `commit` and `on_fire` show the fire under its own id with
//! its newest text, `versions` lists its history, `Purge::Commit` deletes every version, and the
//! writer refuses a replacement nobody would honor.

use crate::common::TestWrites as _;
use crate::common::*;
use osis::internals::costs;
use osis::{Body, CommitEvent, CommitFrom, CommitId, Osis, Tid, Value};
use std::sync::mpsc::{Receiver, channel};

fn log() -> osis::Ak {
    ak("t:log~0")
}

fn key() -> osis::DynamicAspectKey {
    osis::DynamicAspectKey::untyped(log())
}

fn s(x: &str) -> Value {
    Value::Str(x.into())
}

/// A thing keeping its signal's fires for good.
fn thing(db: &Osis) -> Tid {
    let x = crate::common::setting(&[(log().as_str(), osis::History::FOREVER)]);
    db.commit_with(|w| {
        let t = w.create()?;
        w.at(t, osis::core::RETENTION).set(&x)?;
        Ok(t)
    })
    .unwrap()
}

fn fire(db: &Osis, t: Tid, x: &str) -> CommitId {
    let mut w = db.write();
    w.at(t, key()).fire(&s(x)).unwrap();
    w.commit().unwrap().unwrap().stamp.id
}

fn replace(db: &Osis, t: Tid, o: CommitId, x: &str) -> osis::Result<CommitId> {
    let mut w = db.write();
    w.at(t, key()).replace(o, &s(x))?;
    Ok(w.commit()?.unwrap().stamp.id)
}

/// What `t`'s signal lists, oldest first: (id, body, the replacement it reads).
fn listed(db: &Osis, t: Tid) -> Vec<(CommitId, Body<Value>, Option<CommitId>)> {
    let page = db.at(t, key()).fired(&page(CommitFrom::Oldest, 100)).unwrap();
    page.commits.iter().map(|c| {
        let p = part(c, t, &log());
        (c.stamp.id, p.body, p.edited.and_then(|e| e.commit()))
    }).collect()
}

/// `o`'s versions, oldest first: (id, body).
fn versions(db: &Osis, t: Tid, o: CommitId) -> Vec<(CommitId, Body<Value>)> {
    let page = db.at(t, key()).versions(o, &page(CommitFrom::Oldest, 100)).unwrap();
    page.commits.iter().map(|c| {
        let p = part(c, t, &log());
        assert_eq!(p.edited, None, "a version reads as written");
        (c.stamp.id, p.body)
    }).collect()
}

fn held(x: &str) -> Body<Value> {
    Body::Held(Some(s(x)))
}

fn watch(db: &Osis, t: Tid) -> (osis::Subscription, Receiver<CommitEvent>) {
    let (tx, rx) = channel();
    let sub = db.at(t, key()).on_fire(move |_, e| tx.send(e).unwrap()).unwrap();
    (sub, rx)
}

/// The listener's events since the last call: (id, body heard).
fn heard(db: &Osis, t: Tid, rx: &Receiver<CommitEvent>) -> Vec<(CommitId, Option<Body<Value>>)> {
    db.settle();
    rx.try_iter().map(|e| match e {
        CommitEvent::Commit { id, commit } => (id, commit.map(|c| part(&c, t, &log()).body)),
        e => panic!("{e:?}"),
    }).collect()
}

// spec/commits.md §5 Signals, notes/api.md Signals: an edited fire lists in its place under its own
// id, reading its newest text, and the replacement is never listed of its own; `commit` reads it
// the same way; `versions` lists the fire and its replacements, each as written
#[test]
fn a_replaced_fire_reads_in_its_place_spec_commits_5() {
    let db = db(0);
    let t = thing(&db);
    let o = fire(&db, t, "one");
    let other = fire(&db, t, "other");
    let v1 = replace(&db, t, o, "two").unwrap();
    let v2 = replace(&db, t, o, "three").unwrap();
    assert_eq!(listed(&db, t), vec![(o, held("three"), Some(v2)), (other, held("other"), None)]);
    let c = db.at(t, key()).commit(o).unwrap().unwrap();
    assert_eq!((c.stamp.id, part(&c, t, &log()).body), (o, held("three")));
    assert_eq!(db.at(t, key()).commit(v1).unwrap(), None, "a replacement lists under its fire");
    assert_eq!(db.at(t, key()).commit("07".repeat(32).parse::<CommitId>().unwrap()).unwrap(), None);
    assert_eq!(versions(&db, t, o), vec![(o, held("one")), (v1, held("two")), (v2, held("three"))]);
    let newest = db.at(t, key()).versions(o, &page(CommitFrom::Newest, 1)).unwrap();
    assert_eq!((newest.commits.len(), newest.more), (1, true));
    assert_eq!(newest.commits[0].stamp.id, v2);
    assert!(versions(&db, t, v1).is_empty(), "a replacement has no versions of its own");
    assert_eq!(versions(&db, t, other), vec![(other, held("other"))]);
}

// notes/api-design.md (listeners fire once per visible change), spec/commits.md §5 Signals: a
// listener hears an edit once, as a change of the fire, never the replacement's own id; a delete
// once too
#[test]
fn a_listener_hears_an_edit_once_under_the_fire_spec_commits_5() {
    let db = db(0);
    let t = thing(&db);
    let (_sub, rx) = watch(&db, t);
    let o = fire(&db, t, "one");
    assert_eq!(heard(&db, t, &rx), vec![(o, Some(held("one")))]);
    replace(&db, t, o, "two").unwrap();
    assert_eq!(heard(&db, t, &rx), vec![(o, Some(held("two")))]);
    let rq = commit_with(&db, |w| w.at(t, key()).purge(osis::Purge::Commit(o))).stamp.id;
    let got = heard(&db, t, &rx);
    assert!(matches!(got.as_slice(), [(id, Some(Body::Purged { by, .. }))] if *id == o && *by == rq), "{got:?}");
}

// notes/api.md Signals (one way to delete): `Purge::Commit` of a fire purges every version of it
// held here, so no edit shows after a delete; purging the fire in the same write as a replacement
// drops the earlier text and keeps the new
#[test]
fn a_purge_of_a_fire_takes_its_versions_spec_commits_5() {
    let db = db(0);
    let t = thing(&db);
    let o = fire(&db, t, "one");
    let v1 = replace(&db, t, o, "two").unwrap();
    let mut w = db.write();
    w.at(t, key()).replace(o, &s("three")).unwrap();
    w.at(t, key()).purge(osis::Purge::Commit(o)).unwrap();
    let v2 = w.commit().unwrap().unwrap().stamp.id;
    assert_eq!(listed(&db, t), vec![(o, held("three"), Some(v2))], "the new text stays");
    let old = versions(&db, t, o);
    assert!(matches!(old.as_slice(), [(a, Body::Purged { .. }), (b, Body::Purged { .. }), (c, x)] if *a == o && *b == v1 && *c == v2 && *x == held("three")), "{old:?}");
    commit_with(&db, |w| w.at(t, key()).purge(osis::Purge::Commit(o)));
    let got = listed(&db, t);
    assert!(matches!(got.as_slice(), [(a, Body::Purged { .. }, Some(e))] if *a == o && *e == v2), "deleted, no version shows: {got:?}");
    assert!(versions(&db, t, o).iter().all(|(_, b)| matches!(b, Body::Purged { .. })));
}

// spec/commits.md §5 Signals, notes/api-design.md (fast by construction): a page and a quote cost
// the same however many messages and edits there are: bodies read and versions judged are flat
// in n and in the edits of each message
#[test]
fn a_page_and_a_quote_are_flat_in_edits_spec_commits_5() {
    fn count(n: usize, edits: usize) -> Vec<(&'static str, u64)> {
        let db = db(0);
        let t = thing(&db);
        // the quote is of the oldest message: a walk from the newest would pay the whole signal
        let mut first = None;
        for i in 0..n {
            let o = fire(&db, t, &format!("m{i}"));
            for j in 0..edits {
                replace(&db, t, o, &format!("m{i}e{j}")).unwrap();
            }
            first.get_or_insert(o);
        }
        let first = first.unwrap();
        costs::take();
        let page = db.at(t, key()).fired(&page(CommitFrom::Newest, 20)).unwrap();
        assert_eq!(page.commits.len(), 20);
        let at_page = costs::take();
        let q = db.at(t, key()).commit(first).unwrap().unwrap();
        assert_eq!(part(&q, t, &log()).body, held(&format!("m0e{}", edits - 1)));
        let at_quote = costs::take();
        let n = |cs: &[(&str, std::time::Duration, u64)], k: &str| cs.iter().find(|x| x.0 == k).map_or(0, |x| x.2);
        let keys = ["listing: body read", "listing: version judged", "listing: commit read", "listing: place walked"];
        keys.iter().map(|k| (*k, n(&at_page, k))).chain(keys.iter().map(|k| (*k, n(&at_quote, k)))).collect()
    }
    let small = count(30, 3);
    assert_eq!(small[0].1, 21, "one body per entry, and one past the page: {small:?}");
    assert_eq!(small, count(300, 3));
    assert_eq!(small, count(30, 30));
}


// spec/commits.md §5 (fire kept): a writer writes no fire the setting it holds would not keep.
// On a thing with no setting for the signal a fire is refused and nothing is written; on one
// keeping it, the same fire is listed.
#[test]
fn a_fire_no_setting_keeps_is_refused_spec_commits_5() {
    let db = db(0);
    let bare = db.commit_with(|w| w.create()).unwrap();
    let mut w = db.write();
    let r = w.at(bare, key()).fire(&s("unkept")).and_then(|_| w.commit());
    assert!(r.is_err(), "a fire nothing keeps: {r:?}");
    assert!(listed(&db, bare).is_empty(), "nothing written");
    let kept = thing(&db);
    fire(&db, kept, "kept");
    assert_eq!(listed(&db, kept).len(), 1);
}
