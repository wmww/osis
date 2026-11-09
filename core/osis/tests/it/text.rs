//! Text sessions follow their field, whoever writes it (notes/listener-design.md Text sessions;
//! notes/api.md Text editing sessions), and a keystroke never waits for a save.
//! spec: none (API surface, notes/api.md)

use crate::common::TestWrites as _;
use crate::common::*;
use osis::{DynamicAspectKey, MemStore, Osis, Scope, TextSession, Tid, Value};
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Mutex};

const SCHEMA: &str = "revision 1;\nkeep_history(1d) aspect n:body.0: text;\naspect n:title.0: string;\n";

fn setup(db: Osis) -> (Osis, Tid, DynamicAspectKey) {
    db.register_schema("t.osis", SCHEMA).unwrap();
    let title = db.aspect_key("n:title.0").unwrap();
    // a title keeps the thing when its body is removed
    let t = db.commit_with(|w| {
        let t = w.create()?;
        w.at(t, title).set(&Value::Str("t".into()))?;
        Ok(t)
    }).unwrap();
    let k = db.aspect_key("n:body.0").unwrap();
    (db, t, k)
}

fn open(db: &Osis, t: Tid, k: &DynamicAspectKey) -> TextSession {
    db.at(t, k.clone()).path(osis::p![]).edit_text().unwrap()
}

fn field(db: &Osis, t: Tid, k: &DynamicAspectKey) -> Option<String> {
    match db.at(t, k.clone()).get().unwrap() {
        Some(Value::Str(s)) => Some(s),
        None => None,
        v => panic!("not text: {v:?}"),
    }
}

/// The texts `s` reports through `on_merge`, as they arrive.
fn merges(s: &TextSession) -> (osis::Subscription, Receiver<String>) {
    let (tx, rx) = channel();
    let sub = s.on_merge(move |_, text, _| tx.send(text.to_string()).unwrap()).unwrap();
    (sub, rx)
}

/// The commits listed at `k` of `t`, as they arrive.
fn commits(db: &Osis, t: Tid, k: &DynamicAspectKey) -> (osis::Subscription, Receiver<osis::CommitEvent>) {
    let (tx, rx) = channel();
    let sub = db.at(t, k.clone()).on_write(move |_, e| tx.send(e).unwrap()).unwrap();
    (sub, rx)
}

// A `remove` of the field empties an open session and is reported as a merge.
#[test]
fn text_remove_empties_open_session() {
    let (db, t, k) = setup(db(1));
    let s = open(&db, t, &k);
    let (_m, merged) = merges(&s);
    s.edit("", "hello").unwrap();
    s.commit().unwrap().unwrap();
    db.commit_with(|w| w.at(t, k.clone()).remove()).unwrap();
    db.settle();
    assert_eq!(s.text(), "");
    assert_eq!(merged.try_iter().collect::<Vec<_>>(), [""]);
    s.edit("", "new").unwrap();
    s.commit().unwrap().unwrap();
    assert_eq!(field(&db, t, &k).as_deref(), Some("new"), "typing after the remove writes only itself");
}

// Two sessions on one field of one node: each one's typing reaches the other, both texts kept.
#[test]
fn text_two_sessions_keep_both_texts() {
    let (db, t, k) = setup(db(1));
    let (a, b) = (open(&db, t, &k), open(&db, t, &k));
    a.edit("", "one").unwrap();
    b.edit("", "two").unwrap();
    a.commit().unwrap().unwrap();
    // b merges a's commit, committing its own typing first; a then merges b's
    db.settle();
    db.settle();
    let f = field(&db, t, &k).unwrap();
    assert!(f.contains("one") && f.contains("two"), "{f}");
    assert_eq!(a.text(), f);
    assert_eq!(b.text(), f);
    assert_eq!(a.commit().unwrap(), None);
    assert_eq!(b.commit().unwrap(), None);
}

// A session's own commit is its echo: no merge reported, pending typing not committed by it.
#[test]
fn text_own_commit_reports_and_commits_nothing() {
    let (db, t, k) = setup(db(1));
    let s = open(&db, t, &k);
    let (_m, merged) = merges(&s);
    let (_c, listed) = commits(&db, t, &k);
    s.edit("", "a").unwrap();
    s.commit().unwrap().unwrap();
    s.edit("a", "ab").unwrap();
    db.settle();
    assert_eq!(listed.try_iter().count(), 1, "the commit, and no other");
    assert_eq!(merged.try_iter().count(), 0, "nothing merged");
    assert_eq!(s.text(), "ab");
    assert_eq!(field(&db, t, &k).as_deref(), Some("a"), "b still pending");
    s.commit().unwrap().unwrap();
    db.settle();
    assert_eq!(listed.try_iter().count(), 1);
    assert_eq!(merged.try_iter().count(), 0);
}

// An undo of the session's own commit shows in it while it stays open.
#[test]
fn text_undo_shows_in_open_session() {
    let (db, t, k) = setup(db(1));
    let s = open(&db, t, &k);
    let (_m, merged) = merges(&s);
    s.edit("", "hello").unwrap();
    s.commit().unwrap().unwrap();
    s.edit("hello", "hello world").unwrap();
    s.commit().unwrap().unwrap();
    db.undo(&Scope::Thing(t)).unwrap().unwrap();
    db.settle();
    assert_eq!(s.text(), "hello");
    assert_eq!(merged.try_iter().collect::<Vec<_>>(), ["hello"]);
    db.redo(&Scope::Thing(t)).unwrap().unwrap();
    db.settle();
    assert_eq!(s.text(), "hello world");
}

// A save in flight holds no lock a keystroke takes.
// The save stops between its snapshot and its commit until the keystroke has returned; the save
// writes its snapshot, the keystroke stays pending, and nothing is committed twice.
#[test]
fn text_keystroke_does_not_wait_for_a_save() {
    let (saving_tx, saving) = channel();
    let (go, go_rx) = channel::<()>();
    let first = Mutex::new(Some((saving_tx, go_rx)));
    let mut c = cfg(1, MemStore::new(), &clock());
    c.app.internals.text_save = Some(Arc::new(move || {
        if let Some((tx, rx)) = first.lock().unwrap().take() {
            tx.send(()).unwrap();
            rx.recv().unwrap();
        }
    }));
    let (db, t, k) = setup(osis::internals::create(c).unwrap());
    let (_c, listed) = commits(&db, t, &k);
    let s = Arc::new(open(&db, t, &k));
    s.edit("", "a").unwrap();
    let s2 = s.clone();
    let saver = std::thread::spawn(move || s2.commit().unwrap());
    recv(&saving);
    let (typed_tx, typed) = channel();
    let s3 = s.clone();
    let typist = std::thread::spawn(move || {
        s3.edit("a", "ab").unwrap();
        typed_tx.send(s3.text()).unwrap();
    });
    assert_eq!(recv(&typed), "ab", "the keystroke returned while the save was stopped");
    go.send(()).unwrap();
    typist.join().unwrap();
    assert!(saver.join().unwrap().is_some());
    assert_eq!(field(&db, t, &k).as_deref(), Some("a"), "the save wrote its snapshot");
    db.settle();
    assert_eq!(s.text(), "ab", "the echo merged nothing");
    s.commit().unwrap().unwrap();
    assert_eq!(field(&db, t, &k).as_deref(), Some("ab"), "each edit applied once");
    db.settle();
    assert_eq!(listed.try_iter().count(), 2);
}

// A merge whose save is in flight while the user types: the keystroke does not wait, the merge
// commits the typing by another round, and every edit is applied once.
#[test]
fn text_typing_during_a_merge_goes_round_again() {
    let (saving_tx, saving) = channel();
    let (go, go_rx) = channel::<()>();
    let first = Mutex::new(Some((saving_tx, go_rx)));
    let mut c = cfg(1, MemStore::new(), &clock());
    c.app.internals.text_save = Some(Arc::new(move || {
        if let Some((tx, rx)) = first.lock().unwrap().take() {
            tx.send(()).unwrap();
            rx.recv().unwrap();
        }
    }));
    let (db, t, k) = setup(osis::internals::create(c).unwrap());
    let s = open(&db, t, &k);
    let (_m, merged) = merges(&s);
    let (_c, listed) = commits(&db, t, &k);
    s.edit("", "x").unwrap();
    db.commit_with(|w| w.at(t, k.clone()).set(&Value::Str("B".into()))).unwrap();
    // the merge stopped in its save of "x"
    recv(&saving);
    s.edit("x", "xy").unwrap();
    assert_eq!(s.text(), "xy", "the keystroke returned while the merge's save was stopped");
    go.send(()).unwrap();
    db.settle();
    db.settle();
    let f = field(&db, t, &k).unwrap();
    assert!(f.contains('B') && f.contains("xy") && f.len() == 3, "{f}");
    assert_eq!(s.text(), f);
    assert_eq!(merged.try_iter().collect::<Vec<_>>(), std::slice::from_ref(&f));
    assert_eq!(s.commit().unwrap(), None, "nothing left pending");
    assert_eq!(listed.try_iter().count(), 3, "the write, then x, then y");
}

// A merge lands in the buffer after the UI took the text it shows and before its keystroke
// arrives (forced: the keystroke waits for `on_merge`): the keystroke, given as the change of
// the shown text, lands where the user typed it, the merge kept. A position taken from the shown
// text would land inside the merge.
#[test]
fn text_edit_after_an_unshown_merge_lands_where_typed() {
    let (db, t, k) = setup(db(1));
    let s = open(&db, t, &k);
    s.edit("", "hello world").unwrap();
    s.commit().unwrap().unwrap();
    let (_m, merged) = merges(&s);
    let shown = s.text();
    let other = open(&db, t, &k);
    other.edit("hello world", "hello brave world").unwrap();
    other.commit().unwrap().unwrap();
    db.settle();
    assert_eq!(recv(&merged), "hello brave world", "merged into the buffer, not shown");
    s.edit(&shown, "hello world!").unwrap();
    assert_eq!(s.text(), "hello brave world!");
    s.commit().unwrap().unwrap();
    assert_eq!(field(&db, t, &k).as_deref(), Some("hello brave world!"));
}

// An edit into a session whose buffer holds a merge the UI does not show yet keeps the merge
// (`shown` is the UI's text before the keystroke).
#[test]
fn text_edit_keeps_unshown_merge() {
    let (db, t, k) = setup(db(1));
    let s = open(&db, t, &k);
    let shown = "hello world";
    s.edit("", shown).unwrap();
    // the "remote" merge, ahead of the widget
    s.edit(shown, "hello brave world").unwrap();
    s.edit(shown, "hello world!").unwrap();
    assert_eq!(s.text(), "hello brave world!", "after the merge");
    s.edit("hello world!", ">hello world!").unwrap();
    assert_eq!(s.text(), ">hello brave world!", "before the merge");
    s.edit(">hello world!", ">hellX world!").unwrap();
    assert_eq!(s.text(), ">hellX brave world!", "a replace before the merge");
    // " wo" -> "_" is disjoint from the merge read as " brave" after "X": both apply
    s.edit(">hellX world!", ">hellX_rld!").unwrap();
    assert_eq!(s.text(), ">hellX brave_rld!", "a replace right after the merge");
    s.edit(&s.text(), ">hellX brave world!").unwrap();
    // a deletion across the merge point: the merge wins, only what was typed lands, after it
    s.edit(">hellX world!", ">hell_rld!").unwrap();
    assert_eq!(s.text(), ">hellX brave _world!");
    s.edit(">hellX brave _world!", ">hellX brave _world").unwrap();
    assert_eq!(s.text(), ">hellX brave _world", "no merge pending: the plain splice");
}

// Random shown text, merged edit and local edit (one splice each, over a 2-letter alphabet so
// diffs are ambiguous). Disjoint edits give both applied, under some reading of each edit as one
// splice (`aa -> aaa` inserts at any of three points); overlapping ones keep the typed text and
// lose at most the chars the user removed.
#[test]
fn text_edit_random_against_reference() {
    let (db, t, k) = setup(db(1));
    let s = open(&db, t, &k);
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    let mut rnd = move |m: usize| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        (x % m as u64) as usize
    };
    let word = |rnd: &mut dyn FnMut(usize) -> usize, n: usize| -> Vec<char> { (0..rnd(n)).map(|_| if rnd(2) == 0 { 'a' } else { 'b' }).collect() };
    let apply = |t: &[char], at: usize, del: usize, ins: &[char]| -> Vec<char> { [&t[..at], ins, &t[at + del..]].concat() };
    // every (at, del, ins) with apply(a, at, del, ins) == b
    let readings = |a: &[char], b: &[char]| -> Vec<(usize, usize, Vec<char>)> {
        let mut v = vec![];
        for at in 0..=a.len() {
            for del in 0..=a.len() - at {
                let keep = a.len() - del;
                if keep <= b.len() && a[..at] == b[..at] && a[at + del..] == b[b.len() - (a.len() - at - del)..] {
                    v.push((at, del, b[at..b.len() - (a.len() - at - del)].to_vec()));
                }
            }
        }
        v
    };
    let st = |v: &[char]| v.iter().collect::<String>();
    for _ in 0..5000 {
        let sh = word(&mut rnd, 9);
        let (rat, ldat) = (rnd(sh.len() + 1), rnd(sh.len() + 1));
        let (rdel, ldel) = (rnd(sh.len() - rat + 1), rnd(sh.len() - ldat + 1));
        let (rins, lins) = (word(&mut rnd, 4), word(&mut rnd, 4));
        let remote = apply(&sh, rat, rdel, &rins);
        let new = apply(&sh, ldat, ldel, &lins);
        s.edit(&s.text(), &st(&remote)).unwrap();
        s.edit(&st(&sh), &st(&new)).unwrap();
        let got: Vec<char> = s.text().chars().collect();
        let case = format!("shown {:?} remote {:?} new {:?} got {:?}", st(&sh), st(&remote), st(&new), st(&got));
        if ldat + ldel <= rat || ldat >= rat + rdel {
            let mut want = vec![];
            for (ra, rd, ri) in readings(&sh, &remote) {
                for (la, ld, li) in readings(&sh, &new) {
                    if la + ld <= ra {
                        want.push(apply(&remote, la, ld, &li));
                    }
                    if la >= ra + rd {
                        want.push(apply(&remote, la + ri.len() - rd, ld, &li));
                    }
                }
            }
            assert!(want.contains(&got), "{case}: want one of {:?}", want.iter().map(|w| st(w)).collect::<Vec<_>>());
        } else {
            let ok = readings(&sh, &new).into_iter().any(|(_, ld, li)| {
                st(&got).contains(&st(&li)) && got.len() + ld >= remote.len() + li.len() && got.len() <= remote.len() + li.len()
            });
            assert!(ok, "{case}");
        }
    }
}
