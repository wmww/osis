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
use std::collections::{BTreeSet, HashMap};
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
        let d = data();
        d.set_theme("glass").unwrap();
        // home: the account group's collection of favorites, as cards
        let mut w = d.db.write();
        w.at(d.main_group().unwrap(), COLLECTION).set(&Collection { source: Source::Favorites, having: Default::default(), order: Order::Own, arrange: Arrange::Cards, element: None }).unwrap();
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
