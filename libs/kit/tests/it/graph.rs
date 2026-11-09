//! The view graph counts work, never time (notes/fast-design.md): what runs after a change is what
//! read it, nothing runs twice, equal output stops propagation.
use crate::view_tree::data;
use osis::core::{BODY, NAME};
use osis_kit::facets::create;
use osis_kit::schema::{Arrange, COLLECTION, Collection, CollectionOrder as Order, CollectionSource as Source};
use osis_kit::schema::RAW;
use osis_kit::view::{Act, Cx, Graph, Section, Surface, Tree, WindowState};
use osis_kit::views::{open_spec, page};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

fn name(d: &osis_kit::store::Data, t: osis::Tid, n: &str) {
    let mut w = d.db.write();
    w.at(t, NAME).set(&n.to_string()).unwrap();
    w.commit().unwrap();
}

/// The screen a tree draws on: what each path shows, and which paths came and went.
#[derive(Default)]
struct Screen {
    models: HashMap<String, Section>,
    shown: Vec<String>,
}

impl Surface for Screen {
    fn show(&mut self, path: &str, out: &Section) -> osis::Result<bool> {
        self.shown.push(path.to_string());
        Ok(self.models.insert(path.to_string(), out.clone()).as_ref() != Some(out))
    }
    fn gone(&mut self, path: &str) {
        self.models.remove(path);
    }
}

/// `w`, its graph told what it reads.
fn attached<'a>(d: &osis_kit::store::Data, w: &'a WindowState) -> &'a WindowState {
    Cx::new(d, w, false);
    w
}

/// What rendered (`render` nodes), of what a change ran.
fn rendered(keys: &[String]) -> Vec<&String> {
    keys.iter().filter(|k| k.contains("\"render\"")).collect()
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
    assert!(!own.is_empty() && own.iter().all(|k| k.contains(&a.to_string()) || k.contains("\"things\"") || k.contains("\"render\"") || k.contains("aspects")), "only what read the note ran: {own:?}");
}

/// In one cold pass every node (every memo) runs at most once, and the opener's child node, asked
/// for its foot, is not rendered twice.
#[test]
fn no_node_runs_twice_in_a_pass() {
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
    let top = |cx: &Cx| cx.memo(("top", t), |r, &(_, t)| Ok(*r.memo(("length", t), |r, &(_, t)| Ok(r.name(t)?.len()))? + 1)).unwrap();
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
    fn looped(r: &osis_kit::store::Reader, k: &(&'static str, i32)) -> osis::Result<u32> {
        Ok(*r.memo(*k, looped)? + 1)
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

/// What leaves the tree goes, its listeners with it; a local cell stays.
#[test]
fn what_leaves_the_tree_is_freed() {
    let d = data();
    let (a, b) = (create(&d, "tag").unwrap(), d.create_note().unwrap());
    let w = WindowState::default();
    let mut tree = Tree::default();
    tree.show(attached(&d, &w), &mut Screen::default(), &format!("page:{a}"), &open_spec(a)).unwrap();
    let wide = w.graph.len();
    tree.clear(&w, &mut Screen::default());
    tree.show(attached(&d, &w), &mut Screen::default(), &format!("page:{b}"), &open_spec(b)).unwrap();
    assert!(w.graph.len() < wide, "the tag's nodes went: {} then {}", wide, w.graph.len());
    let _: &Rc<Graph> = &w.graph;
}

fn body(d: &osis_kit::store::Data, t: osis::Tid, s: &str) {
    let mut w = d.db.write();
    w.at(t, BODY).set(&s.to_string()).unwrap();
    w.commit().unwrap();
}

/// A parent that handles a dependency's failure reads it again: when the failure ends it updates,
/// and so does what read the parent.
#[test]
fn a_handled_failure_does_not_stick() {
    let d = data();
    let t = d.create_note().unwrap();
    name(&d, t, "bad");
    let w = WindowState::default();
    fn fails(r: &osis_kit::store::Reader, &(_, t): &(&'static str, osis::Tid)) -> osis::Result<usize> {
        let n = r.name(t)?;
        if n == "bad" { Err(osis::Error::Invalid("bad".into())) } else { Ok(n.len()) }
    }
    fn handles(r: &osis_kit::store::Reader, k: &(&'static str, osis::Tid)) -> osis::Result<usize> {
        Ok(r.memo(("fails", k.1), fails).map_or(0, |v| *v))
    }
    fn top(r: &osis_kit::store::Reader, k: &(&'static str, osis::Tid)) -> osis::Result<usize> {
        Ok(*r.memo(("handles", k.1), handles)? + 1)
    }
    let ask = || *Cx::new(&d, &w, false).memo(("top", t), top).unwrap();
    assert_eq!(ask(), 1);
    assert_eq!(ask(), 1, "still failing, still handled");
    name(&d, t, "good");
    assert_eq!(ask(), 5);
}

/// Dependencies that come to form a cycle after a change fail; they do not recurse for ever.
#[test]
fn a_cycle_formed_by_a_change_fails() {
    let d = data();
    let t = d.create_note().unwrap();
    let w = WindowState::default();
    type K = (&'static str, osis::Tid);
    fn a(r: &osis_kit::store::Reader, k: &K) -> osis::Result<u32> {
        if r.name(k.1)? == "loop" { Ok(*r.memo(("b", k.1), b)? + 1) } else { Ok(1) }
    }
    fn b(r: &osis_kit::store::Reader, k: &K) -> osis::Result<u32> {
        Ok(*r.memo(("a", k.1), a)? + 1)
    }
    assert_eq!(*Cx::new(&d, &w, false).memo(("b", t), b).unwrap(), 2);
    name(&d, t, "loop");
    assert!(Cx::new(&d, &w, false).memo(("b", t), b).is_err());
    name(&d, t, "");
    assert_eq!(*Cx::new(&d, &w, false).memo(("b", t), b).unwrap(), 2);
}

/// A diamond: a node reading a memo and what the memo read sees one state, and runs once.
#[test]
fn a_node_never_sees_a_stale_memo() {
    let d = data();
    let t = d.create_note().unwrap();
    name(&d, t, "a");
    let w = WindowState::default();
    type K = (&'static str, osis::Tid);
    fn len(r: &osis_kit::store::Reader, k: &K) -> osis::Result<usize> {
        Ok(r.name(k.1)?.len())
    }
    fn top(r: &osis_kit::store::Reader, k: &K) -> osis::Result<(usize, usize)> {
        Ok((*r.memo(("len", k.1), len)?, r.name(k.1)?.len()))
    }
    assert_eq!(*Cx::new(&d, &w, false).memo(("top", t), top).unwrap(), (1, 1));
    let keys = ran(&w, || {
        name(&d, t, "abc");
        assert_eq!(*Cx::new(&d, &w, false).memo(("top", t), top).unwrap(), (3, 3));
    });
    assert_eq!(keys.iter().filter(|k| k.contains("\"top\"")).count(), 1, "{keys:?}");
}

/// What reads the time depends on the minute tick; what does not, does not.
#[test]
fn a_time_moves_with_the_tick() {
    use osis_kit::view::{TICK, TYPED};
    let d = data();
    let w = WindowState::default();
    type K = (&'static str, ());
    fn clock(r: &osis_kit::store::Reader, _: &K) -> osis::Result<u8> {
        r.now()?;
        Ok(1)
    }
    fn fixed(_: &osis_kit::store::Reader, _: &K) -> osis::Result<u8> {
        Ok(1)
    }
    let pass = || {
        let cx = Cx::new(&d, &w, false);
        cx.memo(("clock", ()), clock).unwrap();
        cx.memo(("fixed", ()), fixed).unwrap();
    };
    pass();
    let keys = ran(&w, || {
        w.set_local(TICK, w.graph.peek(TICK) + 1);
        w.set_local(TYPED, 1);
        pass();
    });
    assert!(keys.iter().any(|k| k.contains("clock")) && !keys.iter().any(|k| k.contains("fixed")), "{keys:?}");
}

/// A change inside a page's content leaves its opener alone (it asked the child only for its foot).
#[test]
fn a_childs_change_stops_at_the_child() {
    let d = data();
    let t = d.create_note().unwrap();
    body(&d, t, "one");
    let w = WindowState::default();
    page(&Cx::new(&d, &w, false), t).unwrap();
    let keys = ran(&w, || {
        body(&d, t, "two");
        page(&Cx::new(&d, &w, false), t).unwrap();
    });
    assert!(!keys.iter().any(|k| k.contains("render") && k.contains("view_type: \"opener\"")), "{keys:?}");
}

/// Passes over a changing page hold the graph's size; a closed window frees the graph.
#[test]
fn nothing_grows_and_a_window_frees_its_graph() {
    let d = data();
    let t = d.create_note().unwrap();
    let w = WindowState::default();
    let mut tree = Tree::default();
    let mut screen = Screen::default();
    tree.show(attached(&d, &w), &mut screen, &format!("page:{t}"), &open_spec(t)).unwrap();
    let mut pass = |i: usize| {
        name(&d, t, &format!("n{i}"));
        d.db.settle();
        tree.update(&w, &mut screen).unwrap();
    };
    pass(0);
    let first = w.graph.len();
    (1..30).for_each(&mut pass);
    assert_eq!(w.graph.len(), first);
    let g = Rc::downgrade(&w.graph);
    drop(w);
    assert!(g.upgrade().is_none(), "nothing keeps a closed window's graph");
}

/// One thing's name at n and 10n things on a page: the work is the same, the nodes grow with n.
#[test]
fn one_write_costs_the_same_at_n_and_10n() {
    let at = |n: usize| {
        let d = data();
        let g = d.main_group().unwrap();
        let mut last = None;
        for i in 0..n {
            let t = d.create_note().unwrap();
            name(&d, t, &format!("n{i}"));
            last = Some(t);
        }
        let w = WindowState::default();
        page(&Cx::new(&d, &w, false), g).unwrap();
        let held = w.graph.len();
        let keys = ran(&w, || {
            name(&d, last.unwrap(), "renamed");
            page(&Cx::new(&d, &w, false), g).unwrap();
        });
        (keys.len(), held)
    };
    let ((a, na), (b, nb)) = (at(5), at(50));
    assert_eq!(a, b, "work of one write at n and 10n");
    assert!(nb <= na * 14, "nodes per thing stay bounded: {na} then {nb}");
}

/// A tree at rest on one note, with a screen: the tree over `d`.
fn on_a_note(d: &osis_kit::store::Data) -> (osis::Tid, WindowState, Tree, Screen) {
    let t = d.create_note().unwrap();
    body(d, t, "one");
    let w = WindowState::default();
    let (mut tree, mut screen) = (Tree::default(), Screen::default());
    tree.show(attached(d, &w), &mut screen, &format!("page:{t}"), &open_spec(t)).unwrap();
    (t, w, tree, screen)
}

/// A dirty node re-renders that one node, and an unrelated write renders nothing.
#[test]
fn only_a_dirty_node_runs() {
    let d = data();
    let (t, w, mut tree, mut screen) = on_a_note(&d);
    let other = d.create_note().unwrap();
    let keys = ran(&w, || {
        name(&d, other, "elsewhere");
        d.db.settle();
        tree.update(&w, &mut screen).unwrap();
    });
    assert_eq!(rendered(&keys).len(), 0, "an unrelated write renders nothing: {keys:?}");
    screen.shown.clear();
    let keys = ran(&w, || {
        body(&d, t, "two");
        d.db.settle();
        tree.update(&w, &mut screen).unwrap();
    });
    // the body's view, and the chrome: what can be undone moved
    let r = rendered(&keys);
    assert_eq!(r.len(), 2, "two nodes: {keys:?}");
    assert!(r.iter().any(|k| k.contains("content:note")) && r.iter().any(|k| k.contains("/chrome\"")), "{r:?}");
    assert!(!r.iter().any(|k| k.contains("\"opener\"") || k.contains("/bar\"")), "{r:?}");
    // an editor's text is the session's: the model is the same, so no slot was rebuilt
    assert!(screen.shown.is_empty(), "{:?}", screen.shown);
}

/// A parent that reruns with a new child keeps its other children unrun, and shows the new one.
#[test]
fn a_parents_rerun_leaves_clean_children() {
    let d = data();
    let (t, w, mut tree, mut screen) = on_a_note(&d);
    let path = format!("page:{t}");
    let keys = ran(&w, || {
        Act::new(&d, &w).set_state(RAW, &path, &true).unwrap();
        d.db.settle();
        tree.update(&w, &mut screen).unwrap();
    });
    let r = rendered(&keys);
    assert!(r.iter().any(|k| k.contains("opener")) && r.iter().any(|k| k.contains("content:raw")), "the opener and its new child: {r:?}");
    assert!(!r.iter().any(|k| k.contains("view_type: \"chrome\"")), "the chrome is clean: {r:?}");
    assert!(screen.models.keys().any(|p| p.contains("content:raw")) && !screen.models.keys().any(|p| p.contains("content:note")), "the old child left: {:?}", screen.models.keys());
}

/// One write of one node's state re-renders that node (a `ui:week.0` entry).
#[test]
fn one_node_state_write_renders_one_node() {
    use osis_kit::schema::WEEK;
    let d = data();
    let cal = create(&d, "tag").unwrap();
    let c = Collection { source: Source::Members, having: Default::default(), order: Order::Name, arrange: Arrange::Days, element: None };
    let mut x = d.db.write();
    x.at(cal, COLLECTION).set(&c).unwrap();
    x.commit().unwrap();
    let (w, mut tree, mut screen) = (WindowState::default(), Tree::default(), Screen::default());
    let spec = osis_kit::view::ViewSpec::new("collection", cal);
    tree.show(attached(&d, &w), &mut screen, "one", &spec).unwrap();
    tree.show(&w, &mut screen, "two", &spec).unwrap();
    let keys = ran(&w, || {
        Act::new(&d, &w).set_state(WEEK, "one", &3).unwrap();
        d.db.settle();
        tree.update(&w, &mut screen).unwrap();
    });
    let r = rendered(&keys);
    assert_eq!(r.len(), 1, "{keys:?}");
    assert!(r[0].contains("\"one\""), "{r:?}");
}

/// A diamond through the tree: a view and its child read one state, and each runs once.
#[test]
fn a_tree_has_no_glitches() {
    let d = data();
    let g = d.main_group().unwrap();
    let n = d.create_note().unwrap();
    name(&d, n, "a");
    let (w, mut tree, mut screen) = (WindowState::default(), Tree::default(), Screen::default());
    tree.show(attached(&d, &w), &mut screen, "page", &open_spec(g)).unwrap();
    let keys = ran(&w, || {
        name(&d, n, "b");
        d.db.settle();
        tree.update(&w, &mut screen).unwrap();
    });
    let distinct: HashSet<&String> = keys.iter().collect();
    assert_eq!(distinct.len(), keys.len(), "nothing ran twice: {keys:?}");
}

/// A render's handle is the one read-only type: osis's compile-fail tests say what it cannot do.
#[test]
fn a_renders_db_is_the_read_only_handle() {
    fn read_only(cx: &Cx) -> &osis::ReadOnly {
        &cx.db
    }
    let d = data();
    let w = WindowState::default();
    let cx = Cx::new(&d, &w, false);
    assert_eq!(read_only(&cx).me(), d.db.me());
}

/// A read does not make the profile: it is made at open, or never without a peer.
#[test]
fn reading_makes_no_profile() {
    let d = data();
    let w = WindowState::default();
    let cx = Cx::new(&d, &w, false);
    assert_eq!(cx.you().unwrap(), None);
}
