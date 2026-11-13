//! The selection menu (a headless `RenderRoot`, events through `input::Input`): when it opens
//! (a touch's long press, a first tap on the selection, a secondary click in a field), what it
//! holds (as the selection and the clipboard allow), where (at the selection, or the pointer),
//! when it closes (a press elsewhere, typing, a scroll, Escape, focus loss) and that its items run
//! the field's own cut, copy and paste. A platform with a menu of its own is asked to show it;
//! one without gets kit's, pressed like any other widget.
use crate::gestures::{FIELD, Screen};
use osis_kit::masonry::app::RenderRootSignal;
use osis_kit::masonry::core::keyboard::{Key, KeyState, KeyboardEvent, NamedKey};
use osis_kit::masonry::core::{PointerButton, PointerEvent, PointerScrollEvent, PointerType, ScrollDelta, TextCommand, TextEvent};
use osis_kit::masonry::dpi::PhysicalPosition;
use osis_kit::masonry::kurbo::{Point, Rect};
use osis_kit::masonry::widgets::{SelectionEnd, TextArea};
use osis_kit::platform::{Place, SelectionMenu};
use osis_kit::widgets::{Menu, MenuItem};

use TextCommand::{Copy, Cut, Paste, SelectAll};

impl Screen {
    /// The window point at the middle of the field's text `start..end`.
    fn at_text(&mut self, start: usize, end: usize) -> Point {
        let id = self.root.get_widget_with_tag(FIELD).unwrap().id();
        self.root.edit_widget(id, |mut w| TextArea::select_byte_range(&mut w.downcast::<TextArea<true>>(), start, end));
        let w = self.root.get_widget_with_tag(FIELD).unwrap();
        let b = w.inner().selection_boxes()[0];
        let p = w.ctx().to_window(b.center());
        self.root.edit_widget(id, |mut w| TextArea::select_byte_range(&mut w.downcast::<TextArea<true>>(), 0, 0));
        p
    }

    fn long_press(&mut self, p: Point) {
        self.down(PointerType::Touch, p, 1000);
        self.hold();
        self.up(PointerType::Touch, p, 50);
    }

    fn tap(&mut self, ty: PointerType, p: Point) {
        self.down(ty, p, 1000);
        self.up(ty, p, 50);
    }

    fn right_click(&mut self, p: Point) {
        self.down_with(PointerType::Mouse, PointerButton::Secondary, p, 1000);
        self.up_with(PointerType::Mouse, PointerButton::Secondary, p, 50);
    }

    /// The platform's menu as last asked for, while it shows.
    fn native(&self) -> Option<&SelectionMenu> {
        self.platform.menus.last().filter(|_| self.platform.shown)
    }

    /// kit's menu, if drawn: its box and its items' commands and boxes.
    fn drawn(&self) -> Option<(Rect, Vec<(TextCommand, Rect)>)> {
        let w = self.root.get_widget(self.input.drawn_menu()?).unwrap();
        let bounds = w.downcast::<Menu>().unwrap().inner().bounds();
        let items = w.children().into_iter().map(|c| {
            let r = c.ctx().bounding_rect();
            (Menu::item_at(&w, r.center()).unwrap(), r)
        });
        let items = items.collect();
        assert!(w.children().iter().all(|c| c.downcast::<MenuItem>().is_some()));
        Some((bounds, items))
    }

    fn drawn_items(&self) -> Vec<TextCommand> {
        self.drawn().map(|(_, i)| i.into_iter().map(|(c, _)| c).collect()).unwrap_or_default()
    }

    /// Taps kit's menu item `c`, by `ty`.
    fn pick(&mut self, ty: PointerType, c: TextCommand) {
        let (_, items) = self.drawn().unwrap();
        let (_, r) = items.into_iter().find(|(i, _)| *i == c).unwrap();
        self.tap(ty, r.center());
    }

    /// Answers the clipboard signals as every shell does (`Ui::copy`, `Ui::paste`).
    fn answer(&mut self) {
        for s in self.signals.try_iter().collect::<Vec<_>>() {
            match s {
                RenderRootSignal::ClipboardStore(t) => self.platform.clipboard = Some(t),
                RenderRootSignal::ClipboardRead => osis_kit::input::paste(&mut self.root, &mut self.platform),
                _ => {}
            }
        }
    }

    fn key(&mut self, key: Key) {
        for state in [KeyState::Down, KeyState::Up] {
            let k = KeyboardEvent { state, key: key.clone(), ..Default::default() };
            self.input.text_event(&mut self.root, &mut self.platform, TextEvent::Keyboard(k));
        }
    }

    fn contents(&self) -> String {
        self.field().text().to_string()
    }
}

/// A long press selects a word and asks the platform's menu for it: cut, copy, paste (the
/// clipboard has text), select all, beside the selection and its handles.
#[test]
fn a_long_press_asks_the_platform_for_its_menu() {
    let mut s = Screen::text();
    s.platform.native = true;
    s.platform.clipboard = Some("hi".into());
    let p = s.at_text(0, 5);
    s.long_press(p);
    assert_eq!(s.selected(), "hello");
    let m = s.native().unwrap().clone();
    assert_eq!(m.items, vec![Cut, Copy, Paste, SelectAll]);
    let Place::Selection(at) = m.at else { panic!("{:?}", m.at) };
    // the word, from its start to its end, down to the handles below it
    let w = s.root.get_widget_with_tag(FIELD).unwrap();
    let word = w.ctx().window_transform().transform_rect_bbox(w.inner().selection_boxes()[0]);
    assert!(word.width() > 10.0 && at.union(word) == at, "{at:?} {word:?}");
    let disc = s.handle(SelectionEnd::Focus);
    assert!(at.y1 > disc.y, "{at:?} handle {disc:?}");
    assert!(s.drawn().is_none());
}

/// Without a platform menu kit draws one; its Copy puts the selection on the clipboard, and its
/// Paste replaces the selection with the clipboard's text.
#[test]
fn kits_menu_copies_and_pastes() {
    let mut s = Screen::text();
    let hello = s.at_text(0, 5);
    let world = s.at_text(6, 11);
    s.long_press(hello);
    assert_eq!(s.drawn_items(), vec![Cut, Copy, SelectAll]);
    let (bounds, _) = s.drawn().unwrap();
    // in a row beside the word: above it when there is room, else below (the field is at the top)
    assert!(bounds.y0 > hello.y && bounds.width() > bounds.height(), "{bounds:?}");
    s.pick(PointerType::Touch, Copy);
    s.answer();
    assert_eq!(s.platform.clipboard.as_deref(), Some("hello"));
    assert!(s.drawn().is_none(), "a pick closes the menu");
    assert_eq!(s.selected(), "hello", "copying leaves the selection");
    s.long_press(world);
    assert_eq!(s.drawn_items(), vec![Cut, Copy, Paste, SelectAll]);
    s.pick(PointerType::Mouse, Paste);
    s.answer();
    assert_eq!(s.contents(), "hello hello");
}

/// A first tap on the selection opens the menu without placing a caret; a tap with it open
/// closes it.
#[test]
fn a_tap_on_the_selection_opens_and_closes_the_menu() {
    let mut s = Screen::text();
    let hello = s.at_text(0, 5);
    s.long_press(hello);
    s.tap(PointerType::Touch, hello);
    assert!(s.drawn().is_none());
    assert_eq!(s.selected(), "hello");
    // a second, later (a first tap again, not a double tap)
    s.tap(PointerType::Touch, hello);
    assert_eq!(s.drawn_items(), vec![Cut, Copy, SelectAll]);
    assert_eq!(s.selected(), "hello");
}

/// A secondary click in a field opens kit's menu at the pointer, in a column; with no selection it
/// holds no cut or copy. A click elsewhere closes it, and so does Escape.
#[test]
fn a_secondary_click_in_a_field_opens_the_menu_at_the_pointer() {
    let mut s = Screen::text();
    s.platform.clipboard = Some("hi".into());
    let world = s.at_text(6, 11);
    s.right_click(world);
    assert_eq!(s.selected(), "");
    assert_eq!(s.drawn_items(), vec![Paste, SelectAll]);
    let (bounds, _) = s.drawn().unwrap();
    assert!((bounds.x0 - world.x).abs() <= 1.0 && (bounds.y0 - world.y).abs() <= 1.0 && bounds.height() > bounds.width() / 2.0, "{bounds:?} at {world:?}");
    s.tap(PointerType::Mouse, Point::new(world.x, 200.0));
    assert!(s.drawn().is_none());
    // on the selection it keeps it
    let start = s.at_text(0, 1) - (3.0, 0.0);
    let on = s.at_text(0, 5);
    s.drag(PointerType::Mouse, start, world, 100);
    let sel = s.selected();
    s.right_click(on);
    assert_eq!(s.selected(), sel);
    assert_eq!(s.drawn_items(), vec![Cut, Copy, Paste, SelectAll]);
    s.key(Key::Named(NamedKey::Escape));
    assert!(s.drawn().is_none());
    assert_eq!(s.selected(), sel);
}

/// The menu closes on typing, a scroll and the field losing the focus, and follows its selection
/// as a handle moves it (the platform's menu is asked again, beside the new selection).
#[test]
fn the_menu_closes_on_typing_scrolling_and_focus_loss_and_follows_a_handle() {
    let mut s = Screen::text();
    s.platform.native = true;
    let hello = s.at_text(0, 5);
    s.long_press(hello);
    s.key(Key::Character("x".into()));
    assert!(s.native().is_none(), "typing closes it");
    assert_eq!(s.contents(), "x world");
    let world = s.at_text(2, 7);
    s.long_press(world);
    assert!(s.native().is_some());
    let delta = ScrollDelta::PixelDelta(PhysicalPosition::new(0.0, -20.0));
    let state = s.state(world, 10, None);
    s.event(PointerEvent::Scroll(PointerScrollEvent { pointer: Screen::info(PointerType::Mouse), delta, state }));
    assert!(s.native().is_none(), "a scroll closes it");
    let state = s.state(world, 10, None);
    s.event(PointerEvent::Scroll(PointerScrollEvent { pointer: Screen::info(PointerType::Mouse), delta: ScrollDelta::PixelDelta(PhysicalPosition::new(0.0, 20.0)), state }));
    s.long_press(world);
    let before = s.native().unwrap().at.rect();
    // the anchor handle dragged to the text's start: the menu moves with the selection
    let h = s.handle(SelectionEnd::Anchor);
    s.down(PointerType::Touch, h, 1000);
    s.move_to(PointerType::Touch, h - (20.0, 0.0), 20);
    s.move_to(PointerType::Touch, h - (200.0, 0.0), 20);
    s.up(PointerType::Touch, h - (200.0, 0.0), 20);
    assert_eq!(s.selected(), "x world");
    let after = s.native().expect("a handle drag keeps the menu").at.rect();
    assert!(after.x0 < before.x0 - 5.0, "{before:?} -> {after:?}");
    s.root.focus_on(None);
    s.input.text_focus(&s.root, &mut s.platform);
    s.input.follow(&mut s.root, &mut s.platform);
    assert!(s.native().is_none(), "losing the focus closes it");
}

/// What the menu offers follows the selection and the clipboard: no cut or copy without a
/// selection, no paste without text to paste, no select all with all selected; Select all keeps
/// the menu open on the new selection.
#[test]
fn the_items_follow_the_selection_and_the_clipboard() {
    let mut s = Screen::text();
    let hello = s.at_text(0, 5);
    s.platform.clipboard = Some(String::new());
    s.long_press(hello);
    assert_eq!(s.drawn_items(), vec![Cut, Copy, SelectAll]);
    s.pick(PointerType::Touch, SelectAll);
    assert_eq!(s.selected(), "hello world");
    assert_eq!(s.drawn_items(), vec![Cut, Copy]);
    s.pick(PointerType::Touch, Cut);
    s.answer();
    assert_eq!((s.contents().as_str(), s.platform.clipboard.as_deref()), ("", Some("hello world")));
    // an empty field: paste alone
    let r = s.rect(FIELD);
    s.long_press(Point::new(r.x0 + 4.0, r.center().y));
    assert_eq!(s.drawn_items(), vec![Paste]);
    s.platform.clipboard = None;
    s.long_press(Point::new(r.x0 + 4.0, r.center().y));
    assert!(s.drawn().is_none(), "a menu with nothing in it does not open");
}

/// A long press on whitespace selects the word nearest it, on either side.
#[test]
fn a_long_press_on_whitespace_takes_the_nearest_word() {
    let mut s = Screen::text_with("hello          world", 1.0);
    let near_world = s.at_text(13, 14);
    let near_hello = s.at_text(6, 7);
    s.long_press(near_world);
    assert_eq!(s.selected(), "world");
    s.long_press(near_hello);
    assert_eq!(s.selected(), "hello");
}

/// A selection handle hangs over the next line: a tap on it is a tap on the text under it (a
/// caret there), and only a drag from it moves the selection's end.
#[test]
fn a_tap_on_a_handle_reaches_the_text_under_it() {
    let mut s = Screen::text_with("hello world\nsecond line", 1.0);
    let hello = s.at_text(0, 5);
    s.long_press(hello);
    assert_eq!(s.selected(), "hello");
    let h = s.handle(SelectionEnd::Anchor);
    s.tap(PointerType::Touch, h);
    let (_, t) = s.root.focused_ime_text().unwrap();
    let (a, f) = t.selection();
    assert_eq!(a, f, "a caret");
    assert!(a > "hello world".len(), "on the second line: {a}");
}
