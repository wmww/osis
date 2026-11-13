//! Touch gestures by pointer type (a headless `RenderRoot`, events through `input::Input`): a touch
//! drag scrolls what is under it and presses nothing, a long press picks up a row or selects a
//! word with handles, a mouse drag reorders and selects as before, and a touch leaves nothing
//! hovered once lifted.
use crate::input::{Recorder, THRESHOLDS};
use osis_kit::input::Input;
use osis_kit::masonry::app::{RenderRoot, RenderRootOptions, RenderRootSignal, WindowSizePolicy};
use osis_kit::masonry::core::{NewWidget, PointerButton, PointerButtonEvent, PointerEvent, PointerId, PointerInfo, PointerState, PointerType, PointerUpdate, Widget, WidgetTag};
use osis_kit::masonry::core::pointer::PointerButtons;
use osis_kit::masonry::dpi::{PhysicalPosition, PhysicalSize};
use osis_kit::masonry::kurbo::{Point, Rect};
use osis_kit::masonry::properties::types::{CrossAxisAlignment, Length};
use osis_kit::masonry::widgets::{Flex, Portal, SelectionEnd, SizedBox, TextArea};
use osis_kit::theme::{Look, Theme};
use osis_kit::widgets::{ListAction, Press, Tile, TileIcon, TileStyle, VirtualList};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, channel};

const ROWS: [WidgetTag<Tile>; 4] = [WidgetTag::new("r0"), WidgetTag::new("r1"), WidgetTag::new("r2"), WidgetTag::new("r3")];
pub(crate) const FIELD: WidgetTag<TextArea<true>> = WidgetTag::new("field");

/// What widgets reported: presses and reorders.
#[derive(Debug, PartialEq)]
enum Did {
    Press,
    Reorder(usize, usize),
}

pub(crate) struct Screen {
    pub(crate) root: RenderRoot,
    pub(crate) signals: Receiver<RenderRootSignal>,
    pub(crate) input: Input,
    pub(crate) platform: Recorder,
    /// Long-press timers started.
    alarms: Rc<RefCell<Vec<u64>>>,
    /// Event time, ns.
    now: u64,
    /// Physical pixels per logical pixel.
    scale: f64,
}

impl Screen {
    pub(crate) fn new(w: NewWidget<dyn Widget>) -> Screen {
        Screen::scaled(w, 1.0)
    }

    pub(crate) fn scaled(w: NewWidget<dyn Widget>, scale: f64) -> Screen {
        let (tx, signals) = channel();
        let opts = RenderRootOptions {
            default_properties: Arc::new(osis_kit::masonry::theme::default_property_set()),
            use_system_fonts: false,
            size_policy: WindowSizePolicy::User,
            size: PhysicalSize::new(400, 300),
            scale_factor: scale,
            test_font: None,
        };
        let mut root = RenderRoot::new(w, move |s| drop(tx.send(s)), opts);
        osis_kit::fonts::register(&mut root);
        let _ = root.redraw();
        let alarms = Rc::new(RefCell::new(Vec::new()));
        let a = alarms.clone();
        let input = Input::new(THRESHOLDS, Box::new(move |seq, _| a.borrow_mut().push(seq)));
        Screen { root, signals, input, platform: Recorder::default(), alarms, now: 1_000_000_000, scale }
    }

    /// A reorderable list of 30 tiles; the first four tagged.
    fn list() -> Screen {
        let look = Arc::new(Look::new(&Theme::named(None), false, None));
        let mut l = VirtualList::new(look.clone(), 100.0, 1, 4.0, false).reorderable(0);
        for i in 0..30 {
            let t = Tile::new(TileStyle::Row, TileIcon::Bar, &format!("row {i}"), "", None, look.clone());
            let w = match ROWS.get(i) {
                Some(tag) => NewWidget::new_with_tag(t, *tag).erased(),
                None => NewWidget::new(t).erased(),
            };
            l = l.with_child(w, false);
        }
        Screen::new(NewWidget::new(l).erased())
    }

    /// A text field at the top of a page that scrolls.
    pub(crate) fn text() -> Screen {
        Screen::text_scaled(1.0)
    }

    fn text_scaled(scale: f64) -> Screen {
        Screen::text_with("hello world", scale)
    }

    /// A text field holding `text` at the top of a page that scrolls.
    pub(crate) fn text_with(text: &str, scale: f64) -> Screen {
        let font = osis_kit::masonry::core::StyleProperty::FontStack(osis_kit::masonry::parley::FontStack::Source("Inter".into()));
        let a = NewWidget::new_with_tag(TextArea::new_editable(text).with_style(font), FIELD);
        let mut col = Flex::column().cross_axis_alignment(CrossAxisAlignment::Fill).with_child(a);
        for _ in 0..40 {
            col = col.with_child(NewWidget::new(SizedBox::empty().height(Length::px(50.0))));
        }
        Screen::scaled(NewWidget::new(Portal::new(NewWidget::new(col)).constrain_horizontal(true)).erased(), scale)
    }

    pub(crate) fn rect<W: Widget>(&self, tag: WidgetTag<W>) -> Rect {
        self.root.get_widget_with_tag(tag).unwrap().ctx().bounding_rect()
    }

    pub(crate) fn event(&mut self, e: PointerEvent) {
        self.input.pointer(&mut self.root, &mut self.platform, e);
    }

    pub(crate) fn info(ty: PointerType) -> PointerInfo {
        PointerInfo { pointer_id: Some(PointerId::PRIMARY), persistent_device_id: None, pointer_type: ty }
    }

    pub(crate) fn state(&mut self, p: Point, ms: u64, button: Option<PointerButton>) -> PointerState {
        self.now += ms * 1_000_000;
        let mut buttons = PointerButtons::new();
        if let Some(b) = button {
            buttons.insert(b);
        }
        PointerState { time: self.now, position: PhysicalPosition::new(p.x * self.scale, p.y * self.scale), buttons, count: 1, scale_factor: self.scale, ..Default::default() }
    }

    pub(crate) fn down_with(&mut self, ty: PointerType, button: PointerButton, p: Point, ms: u64) {
        let state = self.state(p, ms, Some(button));
        self.event(PointerEvent::Down(PointerButtonEvent { button: Some(button), pointer: Self::info(ty), state }));
    }

    pub(crate) fn down(&mut self, ty: PointerType, p: Point, ms: u64) {
        self.down_with(ty, PointerButton::Primary, p, ms);
    }

    pub(crate) fn move_to(&mut self, ty: PointerType, p: Point, ms: u64) {
        let current = self.state(p, ms, Some(PointerButton::Primary));
        self.event(PointerEvent::Move(PointerUpdate { pointer: Self::info(ty), current, coalesced: Vec::new(), predicted: Vec::new() }));
    }

    pub(crate) fn up_with(&mut self, ty: PointerType, button: PointerButton, p: Point, ms: u64) {
        let state = self.state(p, ms, None);
        self.event(PointerEvent::Up(PointerButtonEvent { button: Some(button), pointer: Self::info(ty), state }));
    }

    pub(crate) fn up(&mut self, ty: PointerType, p: Point, ms: u64) {
        self.up_with(ty, PointerButton::Primary, p, ms);
    }

    /// A drag from `a` to `b` in ten steps over `ms`, lifted at `b` at once.
    pub(crate) fn drag(&mut self, ty: PointerType, a: Point, b: Point, ms: u64) {
        self.down(ty, a, 1000);
        for i in 1..=10 {
            self.move_to(ty, a.lerp(b, f64::from(i) / 10.0), ms / 10);
        }
        self.up(ty, b, 0);
    }

    /// The long-press timer of the touch held runs out.
    pub(crate) fn hold(&mut self) {
        let seq = *self.alarms.borrow().last().unwrap();
        self.now += THRESHOLDS.long_press.as_nanos() as u64;
        self.input.long_press(&mut self.root, &mut self.platform, seq);
    }

    /// Animation frames of 16 ms while a fling goes on (at most `n`).
    fn frames(&mut self, n: usize) -> usize {
        let mut ran = 0;
        while self.input.flinging() && ran < n {
            self.input.frame(&mut self.root, 16_000_000);
            ran += 1;
        }
        ran
    }

    fn did(&mut self) -> Vec<Did> {
        let mut out = Vec::new();
        for s in self.signals.try_iter() {
            if let RenderRootSignal::Action(a, _) = s {
                if a.is::<Press>() {
                    out.push(Did::Press);
                } else if let Some(ListAction::Reorder { from, to }) = a.downcast_ref::<ListAction>().copied() {
                    out.push(Did::Reorder(from, to));
                }
            }
        }
        out
    }

    pub(crate) fn selected(&self) -> String {
        let (_, t) = self.root.focused_ime_text().unwrap();
        let (a, f) = t.selection();
        t.text()[a.min(f)..a.max(f)].to_string()
    }

    pub(crate) fn field(&self) -> &TextArea<true> {
        self.root.get_widget_with_tag(FIELD).unwrap().inner()
    }

    /// Where the focused field's handle for `end` is, in the window.
    pub(crate) fn handle(&self, end: SelectionEnd) -> Point {
        let w = self.root.get_widget_with_tag(FIELD).unwrap();
        let (_, c) = w.inner().handle_centres().into_iter().find(|(e, _)| *e == end).unwrap();
        w.ctx().to_window(c)
    }
}

/// A touch swipe up the list scrolls it the swipe's length and records no reorder nor press.
#[test]
fn a_touch_swipe_on_a_list_scrolls_and_reorders_nothing() {
    let mut s = Screen::list();
    let top = s.rect(ROWS[0]).y0;
    let p = s.rect(ROWS[2]).center();
    s.drag(PointerType::Touch, p, p - (0.0, 100.0), 1000);
    assert!((s.rect(ROWS[0]).y0 - (top - 100.0)).abs() < 1.0, "{top} -> {}", s.rect(ROWS[0]).y0);
    assert_eq!(s.did(), vec![]);
}

/// A mouse drag reorders rows and scrolls nothing, as it always did.
#[test]
fn a_mouse_drag_reorders() {
    let mut s = Screen::list();
    let top = s.rect(ROWS[0]).y0;
    let (a, b) = (s.rect(ROWS[0]).center(), s.rect(ROWS[3]).center() + (0.0, 1.0));
    s.drag(PointerType::Mouse, a, b, 200);
    assert_eq!(s.did(), vec![Did::Reorder(0, 3)]);
    assert_eq!(s.rect(ROWS[0]).y0, top);
}

/// A touch held still picks the row up; dragging it then reorders, and nothing is pressed.
#[test]
fn a_long_press_then_drag_reorders() {
    let mut s = Screen::list();
    let (a, b) = (s.rect(ROWS[0]).center(), s.rect(ROWS[3]).center() + (0.0, 1.0));
    s.down(PointerType::Touch, a, 1000);
    s.hold();
    for i in 1..=10 {
        s.move_to(PointerType::Touch, a.lerp(b, f64::from(i) / 10.0), 20);
    }
    s.up(PointerType::Touch, b, 0);
    assert_eq!(s.did(), vec![Did::Reorder(0, 3)]);
    // held without moving: it is put back, nothing pressed
    s.down(PointerType::Touch, a, 1000);
    s.hold();
    s.up(PointerType::Touch, a, 100);
    assert_eq!(s.did(), vec![]);
}

/// A long press is not a tap: a tile outside any list is not pressed by it.
#[test]
fn a_long_press_presses_nothing() {
    let look = Arc::new(Look::new(&Theme::named(None), false, None));
    let t = Tile::new(TileStyle::Row, TileIcon::Bar, "alone", "", None, look);
    let mut s = Screen::new(NewWidget::new_with_tag(t, ROWS[0]).erased());
    let p = s.rect(ROWS[0]).center();
    s.down(PointerType::Touch, p, 1000);
    s.hold();
    s.up(PointerType::Touch, p, 100);
    assert_eq!(s.did(), vec![]);
    s.down(PointerType::Touch, p, 1000);
    s.up(PointerType::Touch, p, 50);
    assert_eq!(s.did(), vec![Did::Press]);
}

/// A touch that turns into a scroll presses nothing where it went down or lifted; a tap does.
#[test]
fn a_tap_presses_and_a_scroll_does_not() {
    let mut s = Screen::list();
    let p = s.rect(ROWS[1]).center();
    s.down(PointerType::Touch, p, 1000);
    s.up(PointerType::Touch, p, 50);
    assert_eq!(s.did(), vec![Did::Press]);
    // moved past the slop: a scroll, lifted over another tile
    s.down(PointerType::Touch, p, 1000);
    s.move_to(PointerType::Touch, p - (0.0, 30.0), 50);
    s.move_to(PointerType::Touch, p - (0.0, 60.0), 50);
    s.up(PointerType::Touch, p - (0.0, 60.0), 200);
    assert_eq!(s.did(), vec![]);
    // down and back
    s.down(PointerType::Touch, p, 1000);
    s.move_to(PointerType::Touch, p - (0.0, 30.0), 50);
    s.move_to(PointerType::Touch, p, 50);
    s.up(PointerType::Touch, p, 200);
    assert_eq!(s.did(), vec![]);
}

/// A flick carries on after the lift and slows to a stop; a touch on the fling stops it there and
/// presses nothing.
#[test]
fn a_fling_carries_on_and_a_touch_stops_it() {
    let mut s = Screen::list();
    let p = s.rect(ROWS[3]).center();
    s.drag(PointerType::Touch, p, p - (0.0, 60.0), 60);
    let lifted = s.rect(ROWS[0]).y0;
    assert!(s.input.flinging());
    s.frames(5);
    let moved = s.rect(ROWS[0]).y0;
    assert!(moved < lifted - 10.0, "{lifted} -> {moved}");
    // caught: it stops, and the touch is no tap
    s.down(PointerType::Touch, p, 0);
    assert!(!s.input.flinging());
    s.up(PointerType::Touch, p, 50);
    assert_eq!(s.did(), vec![]);
    // left alone, a fling slows to a stop
    s.drag(PointerType::Touch, p, p - (0.0, 60.0), 60);
    assert!(s.frames(10_000) < 10_000);
    assert!(!s.input.flinging());
    // a slow drag, or a pause before lifting, flings nothing
    s.drag(PointerType::Touch, p, p - (0.0, 30.0), 3000);
    assert!(!s.input.flinging());
}

/// A tile tapped or scrolled over by a touch is not left hovered once the touch lifts; a mouse
/// over it still hovers it.
#[test]
fn a_lifted_touch_leaves_nothing_hovered() {
    let mut s = Screen::list();
    let hovered = |s: &Screen| s.root.get_widget_with_tag(ROWS[1]).unwrap().ctx().is_hovered();
    let p = s.rect(ROWS[1]).center();
    s.down(PointerType::Touch, p, 1000);
    s.up(PointerType::Touch, p, 50);
    assert!(!hovered(&s));
    s.drag(PointerType::Touch, p + (0.0, 40.0), p, 500);
    assert!(!hovered(&s));
    let hovered = |s: &Screen| s.root.get_widget_with_tag(ROWS[3]).unwrap().ctx().is_hovered();
    s.move_to(PointerType::Mouse, s.rect(ROWS[3]).center(), 10);
    assert!(hovered(&s));
}

/// In text a touch drag scrolls the page and leaves the caret where it was; a tap places it.
#[test]
fn a_touch_drag_in_text_scrolls_without_selecting() {
    let mut s = Screen::text();
    let p = s.rect(FIELD).center() - (s.rect(FIELD).width() / 2.0 - 4.0, 0.0);
    s.down(PointerType::Touch, p, 1000);
    s.up(PointerType::Touch, p, 50);
    let (_, t) = s.root.focused_ime_text().unwrap();
    let caret = t.selection();
    let top = s.rect(FIELD).y0;
    let q = p + (60.0, 0.0);
    s.drag(PointerType::Touch, q, q - (0.0, 80.0), 800);
    assert!((s.rect(FIELD).y0 - (top - 80.0)).abs() < 1.0, "{top} -> {}", s.rect(FIELD).y0);
    let (_, t) = s.root.focused_ime_text().unwrap();
    assert_eq!(t.selection(), caret);
    assert_eq!(s.platform.keyboard, vec![true]);
}

/// A long press selects the word under it and shows handles; dragging a handle moves that end.
#[test]
fn a_long_press_selects_a_word_and_its_handles_adjust_it() {
    let mut s = Screen::text();
    let r = s.rect(FIELD);
    let p = Point::new(r.x0 + r.width().min(80.0) * 0.1 + 2.0, r.center().y);
    s.down(PointerType::Touch, p, 1000);
    s.hold();
    s.up(PointerType::Touch, p, 100);
    assert_eq!(s.selected(), "hello");
    assert!(s.field().has_handles());
    // the selection menu is asked for; the keyboard is not
    assert_eq!(s.platform.menus.len(), 1);
    assert_eq!(s.platform.keyboard, Vec::<bool>::new());
    // the focus handle dragged to the end of the line takes the selection there
    let h = s.handle(SelectionEnd::Focus);
    s.down(PointerType::Touch, h, 1000);
    s.move_to(PointerType::Touch, h + (40.0, 0.0), 20);
    s.move_to(PointerType::Touch, Point::new(r.x1 - 1.0, h.y), 20);
    s.up(PointerType::Touch, Point::new(r.x1 - 1.0, h.y), 20);
    assert_eq!(s.selected(), "hello world");
    assert!(s.field().has_handles());
    // a tap off the selection places a caret: the handles go
    let off = Point::new(r.x1 - 40.0, r.center().y);
    s.down(PointerType::Touch, off, 1000);
    s.up(PointerType::Touch, off, 50);
    assert_eq!(s.selected(), "");
    assert!(!s.field().has_handles());
}

/// A mouse still selects by dragging, and shows no handles.
#[test]
fn a_mouse_drag_in_text_selects() {
    let mut s = Screen::text();
    let r = s.rect(FIELD);
    let (a, b) = (Point::new(r.x0 + 1.0, r.center().y), Point::new(r.x1 - 1.0, r.center().y));
    s.drag(PointerType::Mouse, a, b, 200);
    assert_eq!(s.selected(), "hello world");
    assert_eq!(s.rect(FIELD).y0, r.y0);
    assert!(!s.field().has_handles());
}

/// The soft keyboard is asked for on a tap or click on a field only: not when a drag ends on it,
/// for a scroll, a long press that only selects, or a secondary click.
#[test]
fn only_a_tap_on_a_field_wants_the_keyboard() {
    let mut s = Screen::text();
    let r = s.rect(FIELD);
    let (a, b) = (Point::new(r.x0 + 1.0, r.center().y), Point::new(r.x1 - 1.0, r.center().y));
    // focus it without asking
    s.root.focus_on(Some(s.root.get_widget_with_tag(FIELD).unwrap().id()));
    s.drag(PointerType::Mouse, a, b, 200);
    s.down_with(PointerType::Mouse, PointerButton::Secondary, a, 1000);
    s.up_with(PointerType::Mouse, PointerButton::Secondary, a, 50);
    s.down(PointerType::Touch, a, 1000);
    s.hold();
    s.up(PointerType::Touch, a, 50);
    s.drag(PointerType::Touch, b, b + (0.0, 50.0), 300);
    assert_eq!(s.platform.keyboard, Vec::<bool>::new());
    s.down(PointerType::Mouse, a, 1000);
    s.up(PointerType::Mouse, a, 50);
    assert_eq!(s.platform.keyboard, vec![true]);
}

/// A secondary mouse drag is no drag: it reorders nothing (a long press is a touch's alone).
#[test]
fn a_secondary_mouse_drag_reorders_nothing() {
    let mut s = Screen::list();
    let (a, b) = (s.rect(ROWS[0]).center(), s.rect(ROWS[3]).center() + (0.0, 1.0));
    s.down_with(PointerType::Mouse, PointerButton::Secondary, a, 1000);
    for i in 1..=10 {
        let current = s.state(a.lerp(b, f64::from(i) / 10.0), 20, Some(PointerButton::Secondary));
        s.event(PointerEvent::Move(PointerUpdate { pointer: Screen::info(PointerType::Mouse), current, coalesced: Vec::new(), predicted: Vec::new() }));
    }
    s.up_with(PointerType::Mouse, PointerButton::Secondary, b, 0);
    assert_eq!(s.did(), vec![]);
}

/// A touch the platform cancels ends as nothing: a picked-up row goes back, a held touch is no
/// tap, and its timer running out later does nothing.
#[test]
fn a_cancelled_touch_does_nothing() {
    let mut s = Screen::list();
    let (a, b) = (s.rect(ROWS[0]).center(), s.rect(ROWS[3]).center() + (0.0, 1.0));
    s.down(PointerType::Touch, a, 1000);
    s.hold();
    s.move_to(PointerType::Touch, b, 50);
    s.event(PointerEvent::Cancel(Screen::info(PointerType::Touch)));
    s.up(PointerType::Touch, b, 10);
    assert_eq!(s.did(), vec![]);
    s.down(PointerType::Touch, a, 1000);
    s.event(PointerEvent::Cancel(Screen::info(PointerType::Touch)));
    s.hold();
    s.up(PointerType::Touch, a, 10);
    s.move_to(PointerType::Touch, b, 50);
    assert_eq!(s.did(), vec![]);
    assert!(!s.root.get_widget_with_tag(ROWS[0]).unwrap().ctx().is_hovered());
}

/// A timer from a touch already lifted does nothing to the next touch, which is still a tap.
#[test]
fn a_stale_long_press_timer_does_nothing() {
    let mut s = Screen::list();
    let p = s.rect(ROWS[1]).center();
    s.down(PointerType::Touch, p, 1000);
    s.up(PointerType::Touch, p, 50);
    let stale = *s.alarms.borrow().last().unwrap();
    s.down(PointerType::Touch, p, 1000);
    s.input.long_press(&mut s.root, &mut s.platform, stale);
    s.up(PointerType::Touch, p, 50);
    assert_eq!(s.did(), vec![Did::Press, Did::Press]);
}

/// A fling toward an edge stops there.
#[test]
fn a_fling_stops_at_the_edge() {
    let mut s = Screen::list();
    let top = s.rect(ROWS[0]).y0;
    let p = s.rect(ROWS[1]).center();
    // already at the top: a flick down has nothing to scroll
    s.drag(PointerType::Touch, p, p + (0.0, 60.0), 60);
    s.frames(1);
    assert!(!s.input.flinging());
    assert_eq!(s.rect(ROWS[0]).y0, top);
}

/// At two physical pixels per logical one a touch drag still moves the page with the finger, and a
/// wheel's line and a touchpad's physical pixels scroll the logical distance they say.
#[test]
fn scrolling_follows_the_scale() {
    use osis_kit::masonry::core::{PointerScrollEvent, ScrollDelta};
    let mut s = Screen::text_scaled(2.0);
    let top = s.rect(FIELD).y0;
    let q = s.rect(FIELD).center() + (0.0, 100.0);
    s.drag(PointerType::Touch, q, q - (0.0, 80.0), 800);
    assert!((s.rect(FIELD).y0 - (top - 80.0)).abs() < 1.0, "{top} -> {}", s.rect(FIELD).y0);
    let wheel = |s: &mut Screen, delta| {
        let state = s.state(q, 10, None);
        s.event(PointerEvent::Scroll(PointerScrollEvent { pointer: Screen::info(PointerType::Mouse), delta, state }));
    };
    wheel(&mut s, ScrollDelta::PixelDelta(PhysicalPosition::new(0.0, 40.0)));
    assert!((s.rect(FIELD).y0 - (top - 60.0)).abs() < 1.0, "{top} -> {}", s.rect(FIELD).y0);
    wheel(&mut s, ScrollDelta::LineDelta(0.0, -0.5));
    assert!((s.rect(FIELD).y0 - (top - 120.0)).abs() < 1.0, "{top} -> {}", s.rect(FIELD).y0);
}
