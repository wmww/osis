//! The view graph counts work, never time (notes/fast-design.md): what runs after a change is what
//! read it, nothing runs twice, equal output stops propagation.
use crate::view_tree::data;
use osis::core::{BODY, NAME};
use osis_kit::facets::create;
use osis_kit::schema::{Arrange, COLLECTION, Collection, CollectionOrder as Order, CollectionSource as Source};
use osis_kit::view::{Cx, Graph, WindowState};
use osis_kit::views::page;
use std::collections::HashSet;
use std::rc::Rc;

fn name(d: &osis_kit::store::Data, t: osis::Tid, n: &str) {
    let mut w = d.db.write();
    w.at(t, NAME).set(&n.to_string()).unwrap();
    w.commit().unwrap();
}

fn ran(w: &WindowState, f: impl FnOnce()) -> Vec<String> {
    w.graph.record();
    f();
    w.graph.recorded()
}

/// A second pass with nothing changed runs nothing, however many memos the page reads.
#[test]
fn a_clean_pass_reads_nothing() {
    let d = data();
    let t = d.create_note().unwrap();
    let w = WindowState::default();
    page(&Cx::new(&d, &w, false), t).unwrap();
    assert!(ran(&w, || drop(page(&Cx::new(&d, &w, false), t).unwrap())).is_empty());
}

/// A commit to one thing reruns what read that thing and nothing else; another thing's commit runs
/// nothing here.
#[test]
fn a_commit_reruns_only_what_read_it() {
    let d = data();
    let (a, b) = (d.create_note().unwrap(), d.create_note().unwrap());
    let w = WindowState::default();
    page(&Cx::new(&d, &w, false), a).unwrap();
    let again = |t| page(&Cx::new(&d, &w, false), t).unwrap();
    let other = ran(&w, || {
        name(&d, b, "elsewhere");
        drop(again(a));
    });
    assert!(other.iter().all(|k| !k.contains(&b.to_string())), "another thing's commit runs nothing for it: {other:?}");
    let own = ran(&w, || {
        let mut x = d.db.write();
        x.at(a, BODY).set(&"text".to_string()).unwrap();
        x.commit().unwrap();
        drop(again(a));
    });
    assert!(own.iter().any(|k| k.contains("\"body.0\"")), "the body was read again: {own:?}");
    assert!(!own.is_empty() && own.iter().all(|k| k.contains(&a.to_string()) || k.contains("\"things\"") || k.contains("\"render\"") || k.contains("aspects")), "only what read the note ran: {own:?}");
}

/// In one cold pass every node (every address, every memo) runs at most once, and the opener's
/// child node, asked for its foot, is not rendered twice.
#[test]
fn no_address_is_read_twice_in_a_pass() {
    let d = data();
    let g = d.main_group().unwrap();
    for i in 0..20 {
        let n = d.create_note().unwrap();
        name(&d, n, &format!("n{i}"));
    }
    let w = WindowState::default();
    let keys = ran(&w, || drop(page(&Cx::new(&d, &w, false), g).unwrap()));
    let distinct: HashSet<&String> = keys.iter().collect();
    assert_eq!(distinct.len(), keys.len(), "something ran twice in one pass: {keys:?}");
    assert_eq!(keys.iter().filter(|k| k.contains("\"things\"")).count(), 1, "things read once per pass");
}

/// Equal output stops propagation: a memo reruns when what it read changed, its dependent does not
/// when the memo's value came out the same.
#[test]
fn equal_output_stops_there() {
    let d = data();
    let t = d.create_note().unwrap();
    let w = WindowState::default();
    let cx = Cx::new(&d, &w, false);
    let top = |cx: &Cx| cx.memo(("top", t), move |r| Ok(*r.memo(("length", t), move |r| Ok(r.name(t)?.len()))? + 1)).unwrap();
    assert_eq!(*top(&cx), 1);
    drop(cx);
    let keys = ran(&w, || {
        name(&d, t, ""); // the same length, written
        let cx = Cx::new(&d, &w, false);
        assert_eq!(*top(&cx), 1);
    });
    assert!(!keys.iter().any(|k| k.contains("\"top\"")), "equal output stopped: {keys:?}");
    let keys = ran(&w, || {
        name(&d, t, "x");
        let cx = Cx::new(&d, &w, false);
        assert_eq!(*top(&cx), 2);
    });
    assert!(keys.iter().any(|k| k.contains("\"top\"")), "a different value propagates: {keys:?}");
}

/// A value asked for while it computes (a cycle in a view's data) is an error, not a hang or a
/// stale cache entry.
#[test]
fn a_value_depending_on_itself_fails() {
    let d = data();
    let w = WindowState::default();
    fn looped(r: &osis_kit::store::Reader) -> osis::Result<u32> {
        Ok(*r.memo(("self", 1), looped)? + 1)
    }
    assert!(Cx::new(&d, &w, false).memo(("self", 1), looped).is_err());
}

/// Two collections of everything, sorted by name, summarize without reading each other's summaries.
#[test]
fn collections_of_everything_summarize() {
    let d = data();
    let v = Collection { source: Source::Everything, having: Default::default(), order: Order::Name, arrange: Arrange::Cards, element: None };
    let mut w = d.db.write();
    let (a, b) = (w.create().unwrap(), w.create().unwrap());
    let g = d.main_group().unwrap();
    for (x, n) in [(a, "One"), (b, "Two")] {
        w.at(x, COLLECTION).set(&v).unwrap();
        w.at(x, NAME).set(&n.to_string()).unwrap();
        w.group(g).add(osis::Member::Item(x)).unwrap();
    }
    w.commit().unwrap();
    assert_eq!(d.summary(a).unwrap().sub, "1 item");
    assert_eq!(d.summary(b).unwrap().sub, "1 item");
    let win = WindowState::default();
    let n = page(&Cx::new(&d, &win, false), a).unwrap();
    assert!(!n.walk().is_empty());
}

/// What the pass did not reach goes, its listeners with it (`end_pass`); a local cell stays.
#[test]
fn a_pass_frees_what_it_did_not_reach() {
    let d = data();
    let (a, b) = (create(&d, "tag").unwrap(), d.create_note().unwrap());
    let w = WindowState::default();
    let pass = |t| {
        Graph::begin_pass(&w.graph);
        let n = page(&Cx::new(&d, &w, false), t).unwrap();
        w.graph.end_pass();
        drop(n);
    };
    pass(a);
    let wide = w.graph.len();
    pass(b);
    assert!(w.graph.len() < wide, "the tag's nodes went: {} then {}", wide, w.graph.len());
    let _: &Rc<Graph> = &w.graph;
}
