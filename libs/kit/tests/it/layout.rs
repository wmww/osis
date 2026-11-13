//! The shell's layout follows the space it is given: the rail shows exactly when it and a page
//! fit side by side (a width from the look, not a constant), and Back on a page shows exactly when
//! the rail does not; the screen is rebuilt only when the rail comes or goes. A page fills its
//! height and width: one scrollable reaches all of it at any height, nothing scrolls when
//! everything fits, and a wider window adds columns.
use crate::view_tree::data;
use osis::core::NAME;
use osis_kit::schema::{Arrange, COLLECTION, Collection, CollectionOrder as Order, CollectionSource as Source};
use osis_kit::masonry::accesskit::{Action, ActionRequest, Node, NodeId, Role};
use osis_kit::masonry::app::{RenderRoot, RenderRootOptions, RenderRootSignal, WindowSizePolicy};
use osis_kit::masonry::core::{PointerEvent, PointerId, PointerInfo, PointerScrollEvent, PointerState, PointerType, ScrollDelta, Widget, WidgetId, WidgetRef, WindowEvent};
use osis_kit::masonry::dpi::{PhysicalPosition, PhysicalSize};
use osis_kit::masonry::kurbo::{Point, Rect};
use osis_kit::platform::{Platform, SelectionMenu, Thresholds};
use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::rc::Rc;
use std::sync::mpsc::{Receiver, channel};
use osis_kit::render::{ROOT, Ui, rail_needs, tree};
use osis_kit::store::Data;
use osis_kit::theme::{Look, Theme};
use osis_kit::window::Waker;
use std::sync::Arc;

struct Screen {
    ui: Ui,
    rr: RenderRoot,
    d: Data,
    /// What widgets reported.
    signals: Receiver<RenderRootSignal>,
}

impl Screen {
    /// A note open in a window `width` wide, in `theme`.
    fn new(theme: &str, width: u32) -> Screen {
        let d = data();
        d.set_theme(theme).unwrap();
        let t = d.create_note().unwrap();
        d.set_open(Some(t)).unwrap();
        Screen::show(d, width, 700)
    }

    /// Home in a window `width` by `height`, with `n` favorites named `fav 0`, `fav 1`, ...
    fn home(width: u32, height: u32, n: usize) -> Screen {
        Screen::home_as(width, height, n, Arrange::Cards)
    }

    /// Home with its favorites arranged as `arrange`.
    fn home_as(width: u32, height: u32, n: usize, arrange: Arrange) -> Screen {
        let d = data();
        d.set_theme("glass").unwrap();
        // home: the account group's collection of favorites
        let mut w = d.db.write();
        w.at(d.main_group().unwrap(), COLLECTION).set(&Collection { source: Source::Favorites, having: Default::default(), order: Order::Own, arrange, element: None }).unwrap();
        w.commit().unwrap();
        for i in 0..n {
            let t = d.create_note().unwrap();
            let mut w = d.db.write();
            w.at(t, NAME).set(&format!("fav {i}")).unwrap();
            w.commit().unwrap();
            d.toggle_favorite(t).unwrap();
        }
        d.set_open(None).unwrap();
        Screen::show(d, width, height)
    }

    /// A tag holding `n` notes named `fav 0`, `fav 1`, ... open in a window `width` by `height`:
    /// a page with a bar above its list and the thing's chrome below it.
    fn tag(width: u32, height: u32, n: usize) -> Screen {
        let d = data();
        d.set_theme("glass").unwrap();
        let tag = osis_kit::views::sample_offer(&d, "tag");
        for i in 0..n {
            let t = d.create_note().unwrap();
            let mut w = d.db.write();
            w.at(t, NAME).set(&format!("fav {i}")).unwrap();
            w.commit().unwrap();
            d.add_tag(t, tag).unwrap();
        }
        d.set_open(Some(tag)).unwrap();
        Screen::show(d, width, height)
    }

    fn show(d: Data, width: u32, height: u32) -> Screen {
        let ui = Ui::new(d.clone(), Waker::new(|| {})).unwrap();
        let opts = RenderRootOptions {
            default_properties: Arc::new(osis_kit::masonry::theme::default_property_set()),
            use_system_fonts: false,
            size_policy: WindowSizePolicy::User,
            size: PhysicalSize::new(width, height),
            scale_factor: 1.0,
            test_font: None,
        };
        let (tx, signals) = channel();
        let rr = RenderRoot::new(tree(ui.look()), move |s| drop(tx.send(s)), opts);
        let mut s = Screen { ui, rr, d, signals };
        s.ui.start(&mut s.rr, Box::new(crate::input::Recorder::default()), 1.0, false);
        s.ui.wake(&mut s.rr);
        s
    }

    fn resize(&mut self, width: u32) {
        self.resize_to(width, 700);
    }

    fn resize_to(&mut self, width: u32, height: u32) {
        self.rr.handle_window_event(WindowEvent::Resize(PhysicalSize::new(width, height)));
        self.ui.resized(&mut self.rr, 1.0);
    }

    /// What a screen reader is told: every node by widget.
    fn nodes(&mut self) -> HashMap<u64, Node> {
        self.rr.handle_window_event(WindowEvent::EnableAccessTree);
        let (_, update) = self.rr.redraw();
        update.unwrap().nodes.into_iter().map(|(id, n)| (id.0, n)).collect()
    }

    /// What a screen reader is told is on screen.
    fn labels(&mut self) -> Vec<String> {
        self.nodes().values().filter_map(|n| n.label().map(str::to_string)).collect()
    }

    /// The window's size.
    fn size(&self) -> (f64, f64) {
        let s = self.rr.size();
        (f64::from(s.width), f64::from(s.height))
    }

    /// Each favorite's tile (by label) and its rect in the window.
    fn tiles(&mut self) -> Vec<(String, WidgetId, Rect)> {
        let nodes = self.nodes();
        self.tiles_in(&nodes)
    }

    fn tiles_in(&self, nodes: &HashMap<u64, Node>) -> Vec<(String, WidgetId, Rect)> {
        let mut out = Vec::new();
        fn walk(w: WidgetRef<'_, dyn Widget>, nodes: &HashMap<u64, Node>, out: &mut Vec<(String, WidgetId, Rect)>) {
            if let Some(l) = nodes.get(&w.id().to_raw()).filter(|n| n.role() == Role::Button).and_then(|n| n.label())
                && l.starts_with("fav ")
            {
                out.push((l.split(':').next().unwrap_or_default().to_string(), w.id(), Rect::from_origin_size(w.ctx().window_origin(), w.ctx().size())));
            }
            for c in w.children() {
                walk(c, nodes, out);
            }
        }
        walk(self.rr.get_layer_root(0), nodes, &mut out);
        out
    }

    /// The favorites a user can see: some of the tile in the window, and a press there reaches it.
    fn shown(&mut self) -> BTreeSet<String> {
        let nodes = self.nodes();
        self.shown_in(&nodes)
    }

    fn shown_in(&self, nodes: &HashMap<u64, Node>) -> BTreeSet<String> {
        let (w, h) = self.size();
        let win = Rect::new(0.0, 0.0, w, h);
        let mut out = BTreeSet::new();
        for (label, id, r) in self.tiles_in(nodes) {
            let v = r.intersect(win);
            if v.width() <= 0.0 || v.height() <= 0.0 {
                continue;
            }
            if self.rr.get_layer_root(0).find_widget_under_pointer(v.center()).is_some_and(|hit| hit.id() == id) {
                out.insert(label);
            }
        }
        out
    }

    /// Turns the wheel by `dy` logical px at `at`.
    fn wheel(&mut self, at: Point, dy: f64) {
        let pointer = PointerInfo { pointer_id: Some(PointerId::PRIMARY), persistent_device_id: None, pointer_type: PointerType::Mouse };
        let state = PointerState { position: PhysicalPosition::new(at.x, at.y), ..PointerState::default() };
        self.rr.handle_pointer_event(PointerEvent::Move(osis_kit::masonry::core::PointerUpdate { pointer, current: state.clone(), coalesced: vec![], predicted: vec![] }));
        self.rr.handle_pointer_event(PointerEvent::Scroll(PointerScrollEvent { pointer, delta: ScrollDelta::PixelDelta(PhysicalPosition::new(0.0, -dy)), state }));
        self.ui.wake(&mut self.rr);
        self.rr.redraw();
    }

    /// A touch at `at`, moved by `dy` logical px in ten steps over `ms`, then lifted: a swipe
    /// (`dy` < 0 moves the content up). Returns the time it lifted, ns.
    fn swipe(&mut self, at: Point, dy: f64, ms: u64, t0: u64) -> u64 {
        let pointer = PointerInfo { pointer_id: Some(PointerId::PRIMARY), persistent_device_id: None, pointer_type: PointerType::Touch };
        let state = |p: Point, t: u64| PointerState { time: t, position: PhysicalPosition::new(p.x, p.y), scale_factor: 1.0, ..PointerState::default() };
        let mut t = t0;
        self.ui.pointer(&mut self.rr, PointerEvent::Down(osis_kit::masonry::core::PointerButtonEvent { button: None, pointer, state: state(at, t) }));
        for i in 1..=10 {
            t += ms * 100_000;
            let p = at + (0.0, dy * f64::from(i) / 10.0);
            self.ui.pointer(&mut self.rr, PointerEvent::Move(osis_kit::masonry::core::PointerUpdate { pointer, current: state(p, t), coalesced: vec![], predicted: vec![] }));
        }
        self.ui.pointer(&mut self.rr, PointerEvent::Up(osis_kit::masonry::core::PointerButtonEvent { button: None, pointer, state: state(at + (0.0, dy), t) }));
        self.ui.wake(&mut self.rr);
        self.rr.redraw();
        t
    }

    /// Animation frames of 16 ms, each through what Root reports, as a shell runs them; how many
    /// ran before Root stopped asking (at most `n`).
    fn frames(&mut self, n: usize) -> usize {
        for i in 0..n {
            let mut asked = false;
            for s in self.signals.try_iter().collect::<Vec<_>>() {
                match s {
                    RenderRootSignal::RequestAnimFrame => asked = true,
                    RenderRootSignal::Action(a, w) => self.ui.action(&mut self.rr, w, a),
                    _ => {}
                }
            }
            if !asked {
                return i;
            }
            self.rr.handle_window_event(WindowEvent::AnimFrame(std::time::Duration::from_millis(16)));
            self.rr.redraw();
        }
        n
    }

    /// How many things on screen scroll (offer to scroll or show a bar), and how many of those
    /// hold another.
    fn scrollables(&mut self) -> (usize, usize) {
        let nodes = self.nodes();
        scrollables_in(&nodes)
    }

    /// (the rail's Home row shows, the page's Back to home shows)
    fn rail_and_back(&mut self) -> (bool, bool) {
        let l = self.labels();
        (l.iter().any(|l| l == "osis: Home"), l.iter().any(|l| l == "Home"))
    }

    /// The screen under the root: a new one means everything on it was rebuilt.
    fn screen(&self) -> WidgetId {
        self.rr.get_widget_with_tag(ROOT).unwrap().children()[0].id()
    }
}

fn scrollables_in(nodes: &HashMap<u64, Node>) -> (usize, usize) {
    let scrolls = |id: u64| nodes.get(&id).is_some_and(|n| n.supports_action(Action::ScrollDown) || n.role() == Role::ScrollBar);
    fn below(id: u64, nodes: &HashMap<u64, Node>, f: &dyn Fn(u64) -> bool) -> bool {
        nodes.get(&id).is_some_and(|n| n.children().iter().any(|c| f(c.0) || below(c.0, nodes, f)))
    }
    let all: Vec<u64> = nodes.keys().copied().filter(|id| scrolls(*id)).collect();
    let nested = all.iter().filter(|id| below(**id, nodes, &scrolls)).count();
    (all.len(), nested)
}

fn needs(theme: &str) -> f64 {
    rail_needs(&Look::new(&Theme::named(Some(theme)), false, None))
}

/// A window as wide as the rail and a page need shows the rail and no Back; a pixel less shows
/// Back and no rail. Within each, resizing rebuilds nothing.
#[test]
fn rail_shows_when_it_and_a_page_fit() {
    let at = needs("glass").ceil() as u32;
    let mut s = Screen::new("glass", at);
    assert_eq!(s.rail_and_back(), (true, false), "wide enough at {at}");
    let wide = s.screen();
    s.resize(at + 400);
    assert_eq!(s.screen(), wide, "wider still: nothing rebuilt");
    s.resize(at - 1);
    assert_eq!(s.rail_and_back(), (false, true), "too narrow at {}", at - 1);
    let narrow = s.screen();
    assert_ne!(narrow, wide);
    s.resize(200);
    assert_eq!(s.screen(), narrow, "narrower still: nothing rebuilt");
    assert_eq!(s.rail_and_back(), (false, true));
    s.resize(at);
    assert_eq!(s.rail_and_back(), (true, false));
}

/// The width the rail needs comes from the look: a theme with tighter spacing shows it in a
/// window where a roomier one does not.
#[test]
fn rail_needs_follow_the_look() {
    let (tight, roomy) = (needs("project"), needs("clarity"));
    assert!(tight < roomy, "project {tight}, clarity {roomy}");
    let between = ((tight + roomy) / 2.0) as u32;
    assert_eq!(Screen::new("project", between).rail_and_back(), (true, false));
    let mut s = Screen::new("clarity", between);
    assert_eq!(s.rail_and_back(), (false, true));
    // the theme changing under an open window moves the rail too
    s.d.set_theme("project").unwrap();
    s.ui.wake(&mut s.rr);
    assert_eq!(s.rail_and_back(), (true, false));
}

/// The rail needs its width clear of the window's insets: a side inset arriving after start can
/// take it away, and its going brings it back; top and bottom insets do not count. Insets are
/// physical pixels, so a new scale changes what they cover.
#[test]
fn insets_take_their_width() {
    let at = needs("glass").ceil() as u32;
    let mut s = Screen::new("glass", at + 10);
    assert_eq!(s.rail_and_back(), (true, false));
    s.ui.set_insets(&mut s.rr, [0.0, 300.0, 0.0, 300.0]);
    assert_eq!(s.rail_and_back(), (true, false), "top and bottom");
    s.ui.set_insets(&mut s.rr, [6.0, 0.0, 6.0, 0.0]);
    assert_eq!(s.rail_and_back(), (false, true), "left and right");
    // insets are physical: at twice the scale the same ones cover half as much
    s.rr.handle_window_event(WindowEvent::Rescale(2.0));
    s.rr.handle_window_event(WindowEvent::Resize(PhysicalSize::new(2 * (at + 10), 1400)));
    s.ui.resized(&mut s.rr, 2.0);
    assert_eq!(s.rail_and_back(), (true, false), "at scale 2");
    s.ui.set_insets(&mut s.rr, [12.0, 0.0, 12.0, 0.0]);
    assert_eq!(s.rail_and_back(), (false, true));
    s.ui.set_insets(&mut s.rr, [0.0; 4]);
    assert_eq!(s.rail_and_back(), (true, false));
}

/// At any window height, from very short (a soft keyboard taking most of it) to taller than
/// everything, wheel turns at one place reach every favorite, and one thing scrolls at a time.
#[test]
fn one_scroll_reaches_every_row() {
    let n = 8;
    for h in [60, 190, 700, 4000] {
        let mut s = Screen::home(360, h, n);
        let at = Point::new(180.0, f64::from(h) / 2.0);
        let mut seen = BTreeSet::new();
        for _ in 0..100 {
            let nodes = s.nodes();
            seen.extend(s.shown_in(&nodes));
            let (count, nested) = scrollables_in(&nodes);
            assert!(count <= 1 && nested == 0, "height {h}: {count} scrollables, {nested} nested");
            if seen.len() == n {
                break;
            }
            s.wheel(at, 50.0);
        }
        assert_eq!(seen.len(), n, "height {h}: reached {seen:?}");
    }
}

/// A window taller than the page needs shows no bar and nothing scrolls, at any width.
#[test]
fn nothing_scrolls_when_everything_fits() {
    for (w, h) in [(360, 1600), (700, 1000), (1100, 800)] {
        let mut s = Screen::home(w, h, 6);
        assert_eq!(s.shown().len(), 6, "width {w}");
        assert_eq!(s.scrollables(), (0, 0), "width {w}");
    }
}

/// A wider window puts more favorites side by side: home's cards use the whole width.
#[test]
fn wider_adds_columns() {
    let cols = |w: u32| {
        let mut s = Screen::home(w, 900, 20);
        let tiles = s.tiles();
        let top = tiles.iter().map(|t| t.2.y0).fold(f64::INFINITY, f64::min);
        tiles.iter().filter(|t| (t.2.y0 - top).abs() < 1.0).count()
    };
    let (narrow, wide, wider) = (cols(1100), cols(2200), cols(4400));
    assert!(narrow < wide && wide < wider, "columns at 1100, 2200, 4400: {narrow}, {wide}, {wider}");
}

/// Rows rewrapped at another width keep the same first row at the top.
#[test]
fn rewrapping_keeps_the_top_row() {
    let mut s = Screen::home(1100, 900, 12);
    assert!(s.shown().contains("fav 0"));
    s.resize_to(360, 900);
    assert!(s.shown().contains("fav 0"), "{:?}", s.shown());
}

/// The bar shows on what scrolls: where the rows fit the window but the page around them does
/// not, the one thing offering to scroll moves the page.
#[test]
fn the_bar_is_on_what_scrolls() {
    let n = 8;
    let mut s = Screen::home(900, 700, n);
    assert_eq!(s.shown().len(), n, "every row fits");
    let nodes = s.nodes();
    let scrolls: Vec<u64> = nodes.iter().filter(|(_, n)| n.supports_action(Action::ScrollDown)).map(|(id, _)| *id).collect();
    assert_eq!(scrolls.len(), 1, "the page around the rows does not fit");
    let top = |s: &mut Screen| s.tiles().iter().map(|t| t.2.y0).fold(f64::INFINITY, f64::min);
    let before = top(&mut s);
    s.rr.handle_access_event(ActionRequest { action: Action::ScrollDown, target: NodeId(scrolls[0]), data: None });
    s.rr.redraw();
    assert!(top(&mut s) < before - 1.0, "the rows moved from {before} to {}", top(&mut s));
}

/// Bringing something into view (a screen reader's scroll-into-view) scrolls the page to it:
/// in a short window, what is at the end of a note's page comes into view.
#[test]
fn scroll_into_view_shows_it() {
    let mut s = Screen::new("glass", 360);
    s.resize_to(360, 190);
    let nodes = s.nodes();
    let id = *nodes.iter().find(|(_, n)| n.label() == Some("Undo")).expect("Undo").0;
    fn find(w: WidgetRef<'_, dyn Widget>, id: u64) -> Option<Rect> {
        if w.id().to_raw() == id {
            return Some(Rect::from_origin_size(w.ctx().window_origin(), w.ctx().size()));
        }
        w.children().into_iter().find_map(|c| find(c, id))
    }
    let rect = |s: &Screen| find(s.rr.get_layer_root(0), id).unwrap();
    assert!(rect(&s).y0 >= 190.0, "starts below the window: {:?}", rect(&s));
    s.rr.handle_access_event(ActionRequest { action: Action::ScrollIntoView, target: NodeId(id), data: None });
    s.rr.redraw();
    let r = rect(&s);
    assert!(r.y0 >= 0.0 && r.y1 <= 190.0, "in the window: {r:?}");
}

/// A platform that shares what the keyboard was asked with the test.
struct Keys(Rc<RefCell<Vec<bool>>>);

impl Platform for Keys {
    fn clipboard(&mut self) -> Option<String> {
        None
    }
    fn has_clipboard_text(&mut self) -> bool {
        false
    }
    fn set_clipboard(&mut self, _: String) {}
    fn keyboard(&mut self, wanted: bool) {
        self.0.borrow_mut().push(wanted);
    }
    fn show_selection_menu(&mut self, _: &SelectionMenu) -> bool {
        false
    }
    fn hide_selection_menu(&mut self) {}
    fn thresholds(&self) -> Thresholds {
        crate::input::THRESHOLDS
    }
}

/// Runs the actions widgets reported, as a shell does.
fn pump(ui: &mut Ui, rr: &mut RenderRoot, signals: &Receiver<RenderRootSignal>) {
    for _ in 0..8 {
        let got: Vec<_> = signals.try_iter().collect();
        if got.is_empty() {
            return;
        }
        for s in got {
            if let RenderRootSignal::Action(a, w) = s {
                ui.action(rr, w, a);
            }
        }
        ui.wake(rr);
    }
}

/// Presses what a screen reader calls `label` (or a label starting so), then runs what follows.
/// `seen` gathers the screen reader's tree from its updates, which carry only what changed.
fn press(ui: &mut Ui, rr: &mut RenderRoot, signals: &Receiver<RenderRootSignal>, seen: &mut Vec<(NodeId, String)>, label: &str) {
    rr.handle_window_event(WindowEvent::EnableAccessTree);
    for _ in 0..2 {
        let (_, update) = rr.redraw();
        for (id, n) in update.map(|u| u.nodes).unwrap_or_default() {
            seen.push((id, n.label().unwrap_or_default().to_string()));
        }
        pump(ui, rr, signals);
    }
    // the latest node so called
    let Some(id) = seen.iter().rev().find(|(_, l)| l == label || l.starts_with(&format!("{label}: "))).map(|(id, _)| *id) else {
        panic!("no {label:?} in {:?}", seen.iter().map(|(_, l)| l).collect::<Vec<_>>());
    };
    rr.handle_access_event(ActionRequest { action: Action::Click, target: id, data: None });
    pump(ui, rr, signals);
    ui.wake(rr);
}

/// A thing made from New wants its title typed in: the keyboard is asked for once, when the field
/// appears, and not again when its slot rebuilds (a merge of its title, the screen rebuilt).
#[test]
fn a_new_things_title_asks_for_the_keyboard_once() {
    let d = data();
    let first = d.create_note().unwrap();
    d.set_open(Some(first)).unwrap();
    let ui = Ui::new(d.clone(), Waker::new(|| {})).unwrap();
    let (tx, signals) = channel();
    let opts = RenderRootOptions {
        default_properties: Arc::new(osis_kit::masonry::theme::default_property_set()),
        use_system_fonts: false,
        size_policy: WindowSizePolicy::User,
        size: PhysicalSize::new(1200, 700),
        scale_factor: 1.0,
        test_font: None,
    };
    let rr = RenderRoot::new(tree(ui.look()), move |s| drop(tx.send(s)), opts);
    let keys = Rc::new(RefCell::new(Vec::new()));
    let mut s = Screen { ui, rr, d, signals };
    s.ui.start(&mut s.rr, Box::new(Keys(keys.clone())), 1.0, false);
    s.ui.wake(&mut s.rr);
    let mut seen = Vec::new();
    press(&mut s.ui, &mut s.rr, &s.signals, &mut seen, "New");
    press(&mut s.ui, &mut s.rr, &s.signals, &mut seen, "Note");
    let t = s.d.opened().unwrap().unwrap();
    assert_ne!(t, first);
    assert_eq!(*keys.borrow(), vec![true]);
    let typing = s.rr.focused_ime_text().map(|(id, _)| id).unwrap();
    // another device names it: the merge rebuilds what shows the name
    let mut w = s.d.db.write();
    w.at(t, NAME).set(&"named elsewhere".to_string()).unwrap();
    w.commit().unwrap();
    s.ui.wake(&mut s.rr);
    // the screen rebuilt: the rail goes
    s.resize(300);
    s.ui.wake(&mut s.rr);
    assert_ne!(s.rr.focused_ime_text().map(|(id, _)| id), Some(typing), "rebuilt");
    assert_eq!(*keys.borrow(), vec![true]);
}

/// Touch scrolls the page as the wheel does, in its one-scroll order: in a window too short for
/// home, swipes at one place reach every favorite and back to the top, one thing scrolling at a
/// time; a flick carries on after the lift and stops.
#[test]
fn touch_scrolls_the_page_in_order() {
    let n = 8;
    let mut s = Screen::home(360, 190, n);
    let (low, high) = (Point::new(180.0, 175.0), Point::new(180.0, 15.0));
    let top = |s: &mut Screen| s.tiles().iter().map(|t| t.2.y0).fold(f64::INFINITY, f64::min);
    let start = top(&mut s);
    let mut seen = BTreeSet::new();
    let mut t = 1_000_000_000;
    for _ in 0..100 {
        let nodes = s.nodes();
        seen.extend(s.shown_in(&nodes));
        let (count, nested) = scrollables_in(&nodes);
        assert!(count <= 1 && nested == 0, "{count} scrollables, {nested} nested");
        if seen.len() == n {
            break;
        }
        // slow: no fling
        t = s.swipe(low, -150.0, 2000, t) + 1_000_000_000;
        s.frames(1000);
    }
    assert_eq!(seen.len(), n, "reached {seen:?}");
    for _ in 0..100 {
        if (top(&mut s) - start).abs() < 0.5 {
            break;
        }
        t = s.swipe(high, 150.0, 2000, t) + 1_000_000_000;
        s.frames(1000);
    }
    assert!((top(&mut s) - start).abs() < 0.5, "back at the top: {start} -> {}", top(&mut s));
    // a flick: the page goes on moving after the lift, then stops asking for frames
    s.swipe(low, -40.0, 50, t);
    let lifted = top(&mut s);
    let ran = s.frames(10_000);
    assert!(ran > 1 && ran < 10_000, "{ran} frames");
    assert!(top(&mut s) < lifted - 10.0, "{lifted} -> {}", top(&mut s));
}

/// Every widget a screen reader names as `want` says, outermost first, with its rect in the window,
/// the part of it its clips leave, and the ids of its subtree.
fn named(s: &Screen, nodes: &HashMap<u64, Node>, want: &dyn Fn(&str) -> bool) -> Vec<(String, Rect, Rect, HashSet<WidgetId>)> {
    fn ids(w: WidgetRef<'_, dyn Widget>, out: &mut HashSet<WidgetId>) {
        out.insert(w.id());
        for c in w.children() {
            ids(c, out);
        }
    }
    // what shows of each: its rect within what clips it
    fn walk(w: WidgetRef<'_, dyn Widget>, nodes: &HashMap<u64, Node>, want: &dyn Fn(&str) -> bool, clip: Rect, out: &mut Vec<(String, Rect, Rect, HashSet<WidgetId>)>) {
        let o = w.ctx().window_origin();
        let clip = w.ctx().clip_path().map_or(clip, |c| clip.intersect(c + o.to_vec2()));
        let n = nodes.get(&w.id().to_raw());
        // a text widget's words are in its text runs
        let text = n.map(|n| n.children().iter().filter_map(|c| nodes.get(&c.0)).filter(|c| c.role() == Role::TextRun).filter_map(|c| c.value()).collect::<String>());
        let l = n.and_then(|n| n.label().map(str::to_string)).or(text.filter(|t| !t.is_empty()));
        if let Some(l) = l.filter(|l| want(l)) {
            let mut sub = HashSet::new();
            ids(w, &mut sub);
            let r = Rect::from_origin_size(o, w.ctx().size());
            let shown = r.intersect(clip);
            let shown = if shown.width() > 0.0 && shown.height() > 0.0 { shown } else { Rect::from_origin_size(r.origin(), (0.0, 0.0)) };
            out.push((l.split(':').next().unwrap_or_default().trim().to_string(), r, shown, sub));
            return;
        }
        for c in w.children() {
            walk(c, nodes, want, clip, out);
        }
    }
    let mut out = Vec::new();
    walk(s.rr.get_layer_root(0), nodes, want, Rect::new(f64::NEG_INFINITY, f64::NEG_INFINITY, f64::INFINITY, f64::INFINITY), &mut out);
    out
}

/// What of `named` a user can see: some of it in `win`, and a press there reaches it.
fn seen_in(s: &Screen, nodes: &HashMap<u64, Node>, want: &dyn Fn(&str) -> bool, win: Rect) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (label, _, shown, sub) in named(s, nodes, want) {
        let v = shown.intersect(win);
        if v.width() <= 0.0 || v.height() <= 0.0 {
            continue;
        }
        // some of it shows where a press reaches it (what clips it may leave only a sliver)
        let mut y = v.y0 + 0.5;
        while y < v.y1 {
            if s.rr.get_layer_root(0).find_widget_under_pointer(Point::new(v.center().x, y)).is_some_and(|hit| sub.contains(&hit.id())) {
                out.insert(label.clone());
                break;
            }
            y += 2.0;
        }
    }
    out
}

/// The window's rect.
fn window(s: &Screen) -> Rect {
    let (w, h) = s.size();
    Rect::new(0.0, 0.0, w, h)
}

/// On a thing's page (its bar above the list, its chrome below), at any height from a sliver to
/// taller than everything, wheel turns at one place reach the bar, every row and the chrome, one
/// thing scrolling at a time.
#[test]
fn one_scroll_reaches_every_part() {
    let n = 8;
    let parts = |l: &str| l.starts_with("fav ") || l == "More" || l == "Undo";
    for h in [60, 120, 190, 700, 4000] {
        let mut s = Screen::tag(360, h, n);
        // just inside the page's top (the bar, while it is pinned): the page's edge is 16 px in,
        // and a short page is only a few px above the status line
        let at = Point::new(180.0, 17.0);
        let mut seen = BTreeSet::new();
        for _ in 0..400 {
            let nodes = s.nodes();
            seen.extend(seen_in(&s, &nodes, &parts, window(&s)));
            let (count, nested) = scrollables_in(&nodes);
            assert!(count <= 1 && nested == 0, "height {h}: {count} scrollables, {nested} nested");
            if seen.len() == n + 2 {
                break;
            }
            s.wheel(at, 20.0);
        }
        assert_eq!(seen.len(), n + 2, "height {h}: reached {seen:?}");
    }
}

/// The topmost row that shows, of those named `fav ...`, and its top in the window (where what
/// is off screen sits is not what a user sees).
fn first_row(s: &mut Screen) -> Option<(String, f64)> {
    let nodes = s.nodes();
    let rows = |l: &str| l.starts_with("fav ");
    let seen = seen_in(s, &nodes, &rows, window(s));
    named(s, &nodes, &rows).into_iter().filter(|(l, _, _, _)| seen.contains(l)).map(|(l, r, _, _)| (l, r.y0)).min_by(|a, b| a.1.total_cmp(&b.1))
}

/// A list following its end, scrolled back to the top of its page, keeps the page's order when
/// the window shrinks: what is above the list shows, and right below it the list's first row.
#[test]
fn a_following_list_keeps_the_order_when_the_window_shrinks() {
    let mut s = Screen::home_as(360, 700, 30, Arrange::Stream);
    // back to the top of the page by bringing the search field into view (as focusing it does)
    let nodes = s.nodes();
    let search = *nodes.iter().find(|(_, n)| n.role() == Role::TextInput).expect("the search field").0;
    s.rr.handle_access_event(ActionRequest { action: Action::ScrollIntoView, target: NodeId(search), data: None });
    // the list loads windows towards its start (as a shell answers it) until the field shows
    for _ in 0..20 {
        s.rr.redraw();
        pump(&mut s.ui, &mut s.rr, &s.signals);
    }
    fn find(w: WidgetRef<'_, dyn Widget>, id: u64) -> Option<Rect> {
        if w.id().to_raw() == id {
            return Some(Rect::from_origin_size(w.ctx().window_origin(), w.ctx().size()));
        }
        w.children().into_iter().find_map(|c| find(c, id))
    }
    let field = |s: &Screen| find(s.rr.get_layer_root(0), search).unwrap();
    let top = field(&s);
    assert!(top.y0 >= 0.0 && top.y1 <= 700.0, "the search field shows: {top:?}");
    let (first, y) = first_row(&mut s).expect("a row shows");
    assert!(y > top.y1, "below the field: {first} at {y}");
    for h in [500, 300, 200] {
        s.resize_to(360, h);
        let f = field(&s);
        assert!((f.y0 - top.y0).abs() < 0.5, "height {h}: the top stays: {f:?}");
        // what shows below the field is the list's start: its first row, if any row shows
        if let Some((row, y)) = first_row(&mut s) {
            assert_eq!(row, first, "height {h}: the list's first row comes next");
            assert!(y > f.y1, "height {h}: below the field");
        }
    }
}

/// Rows that fit the window scroll with the page; when the window changes until they no longer
/// fit (the list scrolls its rows) and back, what is at the top stays put.
#[test]
fn no_jump_when_rows_start_or_stop_overflowing() {
    // eight cards in one column at 360: about 1100 px of rows, 300 above, 130 below; scrolled
    // into the rows, short of the end at every height tried
    let mut s = Screen::home(360, 1000, 8);
    for d in [300.0, 10.0, 20.0] {
        s.wheel(Point::new(180.0, 500.0), d);
    }
    let (row, y) = first_row(&mut s).unwrap();
    for h in (1000..1200).step_by(10).chain((1000..1200).rev().step_by(10)) {
        s.resize_to(360, h);
        let (r, y2) = first_row(&mut s).unwrap();
        assert_eq!(r, row, "height {h}");
        assert!((y2 - y).abs() < 0.5, "height {h}: {row} moved from {y} to {y2}");
    }
}

/// Every wheel step moves the page by all of it, also a step crossing from what is above the
/// list into its rows and from its rows into what is below, until the end.
#[test]
fn a_wheel_step_is_never_lost() {
    let mut s = Screen::tag(360, 300, 8);
    let at = Point::new(180.0, 150.0);
    // what shows (what is off screen is not where the one position says until it shows)
    let rows = |s: &mut Screen| {
        let nodes = s.nodes();
        let parts = |l: &str| l.starts_with("fav ") || l == "Undo";
        let seen = seen_in(s, &nodes, &parts, window(s));
        named(s, &nodes, &parts).into_iter().filter(|(l, _, _, _)| seen.contains(l)).map(|(l, r, _, _)| (l, r.y0)).collect::<HashMap<_, _>>()
    };
    let mut before = rows(&mut s);
    let mut moved = 0;
    for _ in 0..200 {
        s.wheel(at, 37.0);
        let after = rows(&mut s);
        let d: Vec<f64> = before.iter().filter_map(|(l, y)| after.get(l).map(|y2| y - y2)).collect();
        // what shows moves by the whole step, until the end
        assert!(!d.is_empty(), "step {moved}: something shows in both");
        if d.iter().all(|d| d.abs() < 0.01) {
            break;
        }
        let step = d[0];
        assert!(d.iter().all(|d| (d - step).abs() < 0.01), "step {moved}: moved by {d:?}");
        if step < 37.0 - 0.01 {
            // a part of a step: the end, where the next moves nothing
            s.wheel(at, 37.0);
            assert_eq!(rows(&mut s), after, "step {moved} stopped short of the end: {step}");
            before = after;
            break;
        }
        moved += 1;
        before = after;
    }
    let undo = before.get("Undo").copied().unwrap();
    assert!(moved > 10 && undo < 300.0, "{moved} steps reached the chrome at {undo}");
}

/// A scroll costs a window of rows, whatever the list's length: rows laid out by one wheel step
/// in the middle of a list of `n` and of `10 n` are the same.
#[test]
fn a_scroll_costs_the_same_at_any_length() {
    let cost = |n: usize| {
        let d = data();
        let tag = osis_kit::views::sample_offer(&d, "tag");
        osis_kit::views::grow_tag(&d, tag, n);
        d.set_open(Some(tag)).unwrap();
        let mut s = Screen::show(d, 360, 400);
        let at = Point::new(180.0, 200.0);
        for _ in 0..20 {
            s.wheel(at, 100.0);
        }
        let before = osis_kit::testing::rows_laid_out();
        s.wheel(at, 100.0);
        osis_kit::testing::rows_laid_out() - before
    };
    let (small, large) = (cost(100), cost(1000));
    assert!(small > 0 && large <= small, "rows laid out by a step: {small} at 100, {large} at 1000");
}

/// The focused text field's caret in the window: the focused widget's IME area as last reported.
fn caret(s: &Screen) -> Option<Rect> {
    let mut at = None;
    for sig in s.signals.try_iter() {
        if let RenderRootSignal::ImeMoved(p, size) = sig {
            at = Some(Rect::from_origin_size((p.x, p.y), (size.width, size.height)));
        }
    }
    at
}

/// A note whose body is `lines` lines long, in a window `width` by `height`.
fn long_note(width: u32, height: u32, lines: usize) -> Screen {
    let d = data();
    d.set_theme("glass").unwrap();
    let t = d.create_note().unwrap();
    let mut w = d.db.write();
    w.at(t, NAME).set(&"long".to_string()).unwrap();
    w.at(t, osis::core::BODY).set(&(0..lines).map(|i| format!("line {i}")).collect::<Vec<_>>().join("\n")).unwrap();
    w.commit().unwrap();
    d.set_open(Some(t)).unwrap();
    Screen::show(d, width, height)
}

/// The note body's text field (the editor whose text starts so).
fn body(s: &mut Screen) -> (WidgetId, Rect) {
    let nodes = s.nodes();
    let (_, r, _, sub) = named(s, &nodes, &|l| l.starts_with("line 0")).into_iter().next().expect("the body");
    let id = *sub.iter().find(|id| s.rr.get_widget(**id).is_some_and(|w| w.ctx().accepts_text_input())).unwrap_or(sub.iter().next().unwrap());
    (id, r)
}

/// A text field taking the focus comes into view at its caret, and stays in view when the space
/// shrinks under it (a soft keyboard's insets, a shorter window).
#[test]
fn a_focused_field_stays_in_view_when_the_space_shrinks() {
    let mut s = long_note(360, 700, 6);
    let (id, _) = body(&mut s);
    s.rr.handle_access_event(ActionRequest { action: Action::Focus, target: NodeId(id.to_raw()), data: None });
    s.rr.redraw();
    assert_eq!(s.rr.focused_widget(), Some(id));
    while caret(&s).is_some() {}
    // a keyboard takes all but 150 px at the bottom
    s.ui.set_insets(&mut s.rr, [0.0, 0.0, 0.0, 550.0]);
    s.rr.redraw();
    let c = caret(&s).or_else(|| {
        s.rr.redraw();
        caret(&s)
    });
    let c = c.expect("the caret was reported");
    assert!(c.y0 >= 0.0 && c.y1 <= 150.0, "the caret above the keyboard: {c:?}");
    s.ui.set_insets(&mut s.rr, [0.0; 4]);
    s.resize_to(360, 120);
    s.rr.redraw();
    if let Some(c) = caret(&s) {
        assert!(c.y0 >= 0.0 && c.y1 <= 120.0, "the caret in a short window: {c:?}");
    }
    let (_, r) = body(&mut s);
    assert!(r.y1 > 0.0 && r.y0 < 120.0, "the body in view: {r:?}");
}

/// A note's body is never shorter than its text: in a window too short for it the page scrolls
/// instead, and the body is as tall as in a window where it has room to spare beyond its text.
#[test]
fn an_editor_is_never_shorter_than_its_text() {
    let height = |h: u32| body(&mut long_note(360, h, 30)).1.height();
    let (short, roomy) = (height(60), height(400));
    assert!(short > 30.0 * 10.0, "thirty lines in {short} px");
    assert!((short - roomy).abs() < 0.5, "{short} at 60 px, {roomy} at 400 px");
}

