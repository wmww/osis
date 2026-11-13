//! Pointer input and the platform surface on real text fields (a headless `RenderRoot`): taps are
//! counted from the platform's thresholds, the soft keyboard is wanted only for a field the user
//! activated or one focused for typing, never for focus alone, and cut, copy and paste go through
//! the platform's clipboard.
use osis_kit::input::Input;
use osis_kit::masonry::app::{RenderRoot, RenderRootOptions, RenderRootSignal, WindowSizePolicy};
use osis_kit::masonry::core::keyboard::{Key, KeyState, KeyboardEvent, Modifiers};
use osis_kit::masonry::core::{NewWidget, PointerButton, PointerButtonEvent, PointerEvent, PointerId, PointerInfo, PointerState, PointerType, TextEvent, WidgetId, WidgetTag};
use osis_kit::masonry::dpi::{PhysicalPosition, PhysicalSize};
use osis_kit::masonry::kurbo::Point;
use osis_kit::masonry::properties::types::CrossAxisAlignment;
use osis_kit::masonry::widgets::{Flex, TextArea};
use osis_kit::platform::{Platform, SelectionMenu, Thresholds};
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

const A: WidgetTag<TextArea<true>> = WidgetTag::new("a");
const B: WidgetTag<TextArea<true>> = WidgetTag::new("b");

pub(crate) const THRESHOLDS: Thresholds = Thresholds { double_tap: Duration::from_millis(300), double_tap_slop: 10.0, long_press: Duration::from_millis(400), touch_slop: 8.0 };

/// A platform that records what it was asked.
#[derive(Default)]
pub(crate) struct Recorder {
    pub(crate) keyboard: Vec<bool>,
    pub(crate) clipboard: Option<String>,
    /// Selection menus asked for, each showing or changing the one shown.
    pub(crate) menus: Vec<SelectionMenu>,
    /// The platform's menu shows (`native`: it has one).
    pub(crate) shown: bool,
    pub(crate) native: bool,
}

impl Platform for Recorder {
    fn clipboard(&mut self) -> Option<String> {
        self.clipboard.clone()
    }
    fn has_clipboard_text(&mut self) -> bool {
        self.clipboard.as_ref().is_some_and(|t| !t.is_empty())
    }
    fn set_clipboard(&mut self, text: String) {
        self.clipboard = Some(text);
    }
    fn keyboard(&mut self, wanted: bool) {
        self.keyboard.push(wanted);
    }
    fn show_selection_menu(&mut self, menu: &SelectionMenu) -> bool {
        self.menus.push(menu.clone());
        self.shown = self.native;
        self.native
    }
    fn hide_selection_menu(&mut self) {
        assert!(self.shown, "hid a menu the platform did not show");
        self.shown = false;
    }
    fn thresholds(&self) -> Thresholds {
        THRESHOLDS
    }
}

struct Screen {
    root: RenderRoot,
    signals: Receiver<RenderRootSignal>,
    input: Input,
    platform: Recorder,
    /// Event time, ns.
    now: u64,
}

impl Screen {
    fn new() -> Screen {
        let (tx, signals) = channel();
        let font = || osis_kit::masonry::core::StyleProperty::FontStack(osis_kit::masonry::parley::FontStack::Source("Inter".into()));
        let a = NewWidget::new_with_tag(TextArea::new_editable("hello world").with_style(font()), A);
        let b = NewWidget::new_with_tag(TextArea::new_editable("second field").with_style(font()), B);
        let col = Flex::column().cross_axis_alignment(CrossAxisAlignment::Fill).with_child(a).with_child(b);
        let opts = RenderRootOptions {
            default_properties: std::sync::Arc::new(osis_kit::masonry::theme::default_property_set()),
            use_system_fonts: false,
            size_policy: WindowSizePolicy::User,
            size: PhysicalSize::new(400, 200),
            scale_factor: 1.0,
            test_font: None,
        };
        let mut root = RenderRoot::new(NewWidget::new(col).erased(), move |s| drop(tx.send(s)), opts);
        osis_kit::fonts::register(&mut root);
        let _ = root.redraw();
        Screen { root, signals, input: Input::new(THRESHOLDS, Box::new(|_, _| {})), platform: Recorder::default(), now: 1_000_000_000 }
    }

    fn id(&self, tag: WidgetTag<TextArea<true>>) -> WidgetId {
        self.root.get_widget_with_tag(tag).unwrap().id()
    }

    /// A point in the field, `x` logical pixels from its left edge.
    fn at(&self, tag: WidgetTag<TextArea<true>>, x: f64) -> Point {
        let r = self.root.get_widget(self.id(tag)).unwrap().ctx().bounding_rect();
        Point::new(r.x0 + x, r.center().y)
    }

    fn event(&mut self, e: PointerEvent) {
        self.input.pointer(&mut self.root, &mut self.platform, e);
    }

    /// A touch down and up at `p`, `gap_ms` after the last event.
    fn tap(&mut self, p: Point, gap_ms: u64) {
        self.now += gap_ms * 1_000_000;
        let pointer = PointerInfo { pointer_id: Some(PointerId::PRIMARY), persistent_device_id: None, pointer_type: PointerType::Touch };
        let state = PointerState { time: self.now, position: PhysicalPosition::new(p.x, p.y), count: 1, scale_factor: 1.0, ..Default::default() };
        self.event(PointerEvent::Down(PointerButtonEvent { button: Some(PointerButton::Primary), pointer, state: state.clone() }));
        self.now += 50_000_000;
        self.event(PointerEvent::Up(PointerButtonEvent { button: Some(PointerButton::Primary), pointer, state: PointerState { time: self.now, ..state } }));
    }

    /// The focused field's selected text.
    fn selected(&self) -> String {
        let (_, t) = self.root.focused_ime_text().unwrap();
        let (a, f) = t.selection();
        t.text()[a.min(f)..a.max(f)].to_string()
    }

    fn focused(&self) -> Option<WidgetId> {
        self.root.focused_ime_text().map(|(id, _)| id)
    }

    /// Ctrl+`letter` to the focused field.
    fn shortcut(&mut self, letter: &str) {
        for state in [KeyState::Down, KeyState::Up] {
            let k = KeyboardEvent { state, key: Key::Character(letter.into()), modifiers: Modifiers::CONTROL, ..Default::default() };
            self.root.handle_text_event(TextEvent::Keyboard(k));
        }
    }

    /// Answers the clipboard signals as every shell does (`Ui::copy`, `Ui::paste`); true if a
    /// paste was asked.
    fn clipboard_signals(&mut self) -> bool {
        let mut asked = false;
        for s in self.signals.try_iter().collect::<Vec<_>>() {
            match s {
                RenderRootSignal::ClipboardStore(t) => self.platform.set_clipboard(t),
                RenderRootSignal::ClipboardRead => {
                    asked = true;
                    osis_kit::input::paste(&mut self.root, &mut self.platform);
                }
                _ => {}
            }
        }
        asked
    }

    fn text(&self, tag: WidgetTag<TextArea<true>>) -> String {
        self.root.get_widget_with_tag(tag).unwrap().inner().text().to_string()
    }
}

#[test]
fn focus_alone_wants_no_keyboard() {
    let mut s = Screen::new();
    let a = s.id(A);
    assert!(s.root.focus_on(Some(a)));
    assert_eq!(s.focused(), Some(a));
    s.input.text_focus(&s.root, &mut s.platform);
    assert_eq!(s.platform.keyboard, Vec::<bool>::new());
}

#[test]
fn a_tap_on_a_field_wants_the_keyboard_and_so_does_a_tap_on_the_focused_one() {
    let mut s = Screen::new();
    let p = s.at(A, 4.0);
    s.tap(p, 1000);
    assert_eq!(s.focused(), Some(s.id(A)));
    assert_eq!(s.platform.keyboard, vec![true]);
    // the keyboard put away, the field kept the focus: a tap brings it back
    let p = s.at(A, 30.0);
    s.tap(p, 1000);
    assert_eq!(s.platform.keyboard, vec![true, true]);
}

#[test]
fn a_field_marked_for_typing_takes_focus_and_wants_the_keyboard() {
    let mut s = Screen::new();
    let b = s.id(B);
    s.input.type_in(&mut s.root, &mut s.platform, b);
    assert_eq!(s.focused(), Some(b));
    assert_eq!(s.platform.keyboard, vec![true]);
}

#[test]
fn losing_the_text_field_does_not_want_the_keyboard() {
    let mut s = Screen::new();
    let p = s.at(A, 4.0);
    s.tap(p, 1000);
    s.root.focus_on(None);
    s.input.text_focus(&s.root, &mut s.platform);
    assert_eq!(s.platform.keyboard, vec![true, false]);
}

#[test]
fn taps_count_within_the_platforms_time_and_distance() {
    let mut s = Screen::new();
    let p = s.at(A, 8.0);
    s.tap(p, 1000);
    assert_eq!(s.selected(), "");
    // a second tap soon after and near: a word
    s.tap(p + (3.0, 0.0), 100);
    assert_eq!(s.selected(), "hello");
    // a third: the line
    s.tap(p, 100);
    assert_eq!(s.selected(), "hello world");
    // a fourth starts over: a caret
    s.tap(p, 100);
    assert_eq!(s.selected(), "");
    // too late: two single taps
    s.tap(p, 1000);
    s.tap(p, 400);
    assert_eq!(s.selected(), "");
    // too far: two single taps
    s.tap(p, 1000);
    s.tap(p + (30.0, 0.0), 100);
    assert_eq!(s.selected(), "");
}

#[test]
fn cut_copy_and_paste_go_through_the_platforms_clipboard() {
    let mut s = Screen::new();
    let p = s.at(A, 8.0);
    s.tap(p, 1000);
    s.tap(p, 100);
    assert_eq!(s.selected(), "hello");
    s.shortcut("c");
    assert!(!s.clipboard_signals());
    assert_eq!(s.platform.clipboard.as_deref(), Some("hello"));
    s.shortcut("x");
    s.clipboard_signals();
    assert_eq!(s.text(A), " world");
    // paste asks the platform: nothing is typed until it answers
    s.platform.clipboard = Some("hi".into());
    s.shortcut("v");
    assert_eq!(s.text(A), " world");
    assert!(s.clipboard_signals());
    assert_eq!(s.text(A), "hi world");
    // an empty clipboard pastes nothing: the selection stays
    s.tap(p, 1000);
    s.tap(p, 100);
    assert_eq!(s.selected(), "hi");
    s.platform.clipboard = Some(String::new());
    s.shortcut("v");
    assert!(s.clipboard_signals());
    assert_eq!(s.text(A), "hi world");
    assert_eq!(s.selected(), "hi");
}
