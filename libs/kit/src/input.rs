//! Pointer input in common code (notes/app.md, Platforms and input): every shell's pointer events
//! pass through `Input` on their way to the `RenderRoot`. It recognises gestures from the
//! platform's thresholds, by the pointer's type and never by the platform, and decides when the
//! soft keyboard is wanted.
//!
//! A mouse goes straight through; `Input` only counts its clicks (double and triple). A touch (a
//! pen too) is held back until it is clear what it is, so a widget sees only what the touch meant:
//! - a **tap** (lifted before moving past the touch slop and before the long-press time) reaches
//!   widgets as a press and a release at once, its taps counted as clicks are;
//! - a **scroll** (moved past the slop first) reaches them as scroll events where it went down,
//!   the finger's movement, then a fling decaying from the speed it was lifted at; no press;
//! - a **long press** (held still past the long-press time) reaches them as the touch's secondary
//!   press, then moves and a release with that button: a widget that acts on a primary press
//!   ignores it, one that has a long-press meaning (text, a reorderable list) takes it.
//!
//! A touch on the focused field's selection handle drags that handle once it moves past the slop;
//! lifted before, it is a tap on what is under it (the handle hangs over the next line). While
//! held still a touch shows as a hover; lifted, or once it scrolls, nothing is hovered. A touch
//! that lands on a fling stops it and is nothing else. Other fingers while one is followed are
//! left out.
//!
//! The soft keyboard: focus never shows it by itself; a tap or click (a primary press released
//! within the slop of where it went down) over the focused text field does, and so does a field
//! focused for the user to type in now (`type_in`).
//!
//! The selection menu (the focused field's cut, copy, paste and select all, as its selection and
//! the clipboard allow) is for the field's selection as it was when it opened. It opens after a
//! touch's long press in the field, on a touch's first tap on the selection (which places no
//! caret; a tap with the menu open closes it), and on a secondary click in the field (at the pointer). It
//! closes at the next press (one on a handle adjusts its selection and keeps it; one on kit's menu
//! is the menu's), a wheel scroll, Escape, Back, a pick, and when the field loses focus, its text
//! changes or its selection collapses; any other change of the selection (a handle dragged,
//! Select all) moves it along. The platform shows its own menu where it has one; else kit draws it
//! (`widgets::Menu`), taking presses on it here, since it acts on the focused field and must not
//! take the focus. A pick runs the field's own command (`TextEvent::Command`), as its shortcut
//! does.

use crate::masonry::app::RenderRoot;
use crate::masonry::core::keyboard::{Key, KeyState, NamedKey};
use crate::masonry::core::{Handled, NewWidget, PointerButton, PointerButtonEvent, PointerEvent, PointerId, PointerInfo, PointerScrollEvent, PointerState, PointerType, PointerUpdate, ScrollDelta, TextCommand, TextEvent, WidgetId};
use crate::masonry::core::pointer::PointerButtons;
use crate::masonry::dpi::PhysicalPosition;
use crate::masonry::kurbo::{Point, Vec2};
use crate::masonry::widgets::{SelectionEnd, TextArea};
use crate::platform::{Place, Platform, SelectionMenu, Thresholds};
use crate::theme::{Look, Theme};
use crate::widgets::Menu;
use std::sync::Arc;
use std::time::Duration;

/// A fling's speed falls by a factor e every this many seconds (Minor: how far a flick carries;
/// at 0 a lift stops dead, at infinity a fling never slows).
const FLING_TAU: f64 = 0.325;
/// How far back a lift's speed is measured, ns (Minor: at 0 only the last move's jitter counts,
/// at infinity the whole drag's mean, so a slow start dulls a flick; a pause this long before
/// lifting flings nothing).
const VELOCITY_WINDOW: u64 = 100_000_000;

/// Starts the long-press timer: `alarm(seq, after)` must have the shell call `Input::long_press`
/// with `seq` once `after` has passed (`Ui`: a thread that sleeps, then wakes the shell's `Waker`).
pub type Alarm = Box<dyn FnMut(u64, Duration)>;

/// The last tap or click: its pointer, where it went down (logical), when it went up (ns, `None`
/// while held), how many taps it ends, and whether it follows none (a fourth tap counts 1 again,
/// but still follows).
struct Tap {
    pointer: Option<PointerId>,
    at: Point,
    up: Option<u64>,
    count: u8,
    fresh: bool,
}

/// The mouse press held: a click unless it moved past the slop or was not the primary button.
struct Click {
    pointer: Option<PointerId>,
    at: Point,
    click: bool,
}

/// A handle of `field`'s selection: which end, and the offset from a touch to its caret.
type Handle = (WidgetId, SelectionEnd, Vec2);

/// The touch followed, by what it is so far.
enum Touch {
    /// Down, nothing delivered but a hover. `caught`: it landed on a fling, so it is no tap.
    /// `handle`: it landed on a selection handle, which it drags once it moves.
    Held { down: PointerButtonEvent, seq: u64, caught: bool, handle: Option<Handle> },
    /// Delivered as a long press (the secondary press).
    Long { pointer: PointerInfo },
    /// Scrolling what is under `at` (where it went down); `samples` (time, point) for the speed.
    Scroll { pointer: PointerInfo, at: PointerState, last: Point, samples: Vec<(u64, Point)> },
    /// Dragging the selection handle of `field` at `end`; `offset` from the touch to its caret.
    Handle { pointer: PointerInfo, field: WidgetId, end: SelectionEnd, offset: Vec2 },
}

impl Touch {
    fn pointer(&self) -> Option<PointerId> {
        match self {
            Touch::Held { down, .. } => down.pointer.pointer_id,
            Touch::Long { pointer } | Touch::Scroll { pointer, .. } | Touch::Handle { pointer, .. } => pointer.pointer_id,
        }
    }
}

/// A scroll going on by itself after a lift: `v` in logical px/s.
struct Fling {
    pointer: PointerInfo,
    at: PointerState,
    v: Vec2,
}

/// The selection menu shown: for the focused field's selection as it was then.
struct Shown {
    field: WidgetId,
    revision: u64,
    selection: (usize, usize),
    /// Opened at a pointer (a secondary click): it stays there; else beside the selection.
    pointer: Option<Point>,
    /// The clipboard had text to paste when it opened.
    paste: bool,
    menu: SelectionMenu,
    /// kit's drawing of it (its layer's root), where the platform has no menu of its own.
    drawn: Option<WidgetId>,
}

pub struct Input {
    thresholds: Thresholds,
    alarm: Alarm,
    last: Option<Tap>,
    click: Option<Click>,
    touch: Option<Touch>,
    fling: Option<Fling>,
    /// The last long-press timer started.
    seq: u64,
    menu: Option<Shown>,
    /// The menu was open at the last press (a tap on the selection then closes it, opens none).
    was_open: bool,
    /// A press on kit's menu: its pointer and the item it went down on.
    pressing: Option<(Option<PointerId>, Option<TextCommand>)>,
    /// What kit's menu is drawn in.
    look: Arc<Look>,
}

impl Input {
    pub fn new(thresholds: Thresholds, alarm: Alarm) -> Input {
        let look = Arc::new(Look::new(&Theme::named(None), false, None));
        Input { thresholds, alarm, last: None, click: None, touch: None, fling: None, seq: 0, menu: None, was_open: false, pressing: None, look }
    }

    /// kit's drawing of the selection menu, if it shows: its layer's root (a `widgets::Menu`).
    pub fn drawn_menu(&self) -> Option<WidgetId> {
        self.menu.as_ref().and_then(|m| m.drawn)
    }

    /// kit's menu drawn in `look`.
    pub fn with_look(mut self, look: Arc<Look>) -> Input {
        self.look = look;
        self
    }

    /// kit's menu is drawn in `look` (one shown is drawn again).
    pub fn set_look(&mut self, rr: &mut RenderRoot, platform: &mut dyn Platform, look: Arc<Look>) {
        self.look = look;
        if self.drawn_menu().is_some() {
            self.present(rr, platform);
        }
    }

    /// Delivers `e` to `rr` as part of the gesture it belongs to.
    pub fn pointer(&mut self, rr: &mut RenderRoot, platform: &mut dyn Platform, e: PointerEvent) {
        if self.on_menu(rr, platform, &e) {
            return;
        }
        let touch = info(&e).is_some_and(|p| matches!(p.pointer_type, PointerType::Touch | PointerType::Pen));
        if let PointerEvent::Down(b) = &e {
            self.was_open = self.menu.is_some();
            if !(touch && handle_under(rr, b.state.logical_point(), self.thresholds.touch_slop).is_some()) {
                self.close(rr, platform);
            }
        }
        if matches!(e, PointerEvent::Scroll(_)) {
            self.close(rr, platform);
        }
        if touch {
            self.touch(rr, platform, e);
        } else {
            self.mouse(rr, platform, e);
        }
        self.follow(rr, platform);
    }

    /// A press on kit's menu and what follows it, which go to the menu alone: true when `e` was
    /// one of them.
    fn on_menu(&mut self, rr: &mut RenderRoot, platform: &mut dyn Platform, e: &PointerEvent) -> bool {
        let Some(id) = self.menu.as_ref().and_then(|m| m.drawn) else { return false };
        let pointer = info(e).and_then(|p| p.pointer_id);
        let pressing = self.pressing.is_some_and(|(p, _)| p == pointer);
        let item_at = |rr: &RenderRoot, p: Point| rr.get_widget(id).and_then(|w| Menu::item_at(&w, p));
        match e {
            PointerEvent::Down(b) => {
                let p = b.state.logical_point();
                let inside = rr.get_widget(id).and_then(|w| w.downcast::<Menu>().map(|m| m.inner().bounds().contains(p))).unwrap_or(false);
                if inside {
                    self.pressing = Some((pointer, item_at(rr, p)));
                }
                inside
            }
            PointerEvent::Up(b) if pressing => {
                let item = self.pressing.take().and_then(|(_, i)| i);
                if let Some(c) = item.filter(|c| item_at(rr, b.state.logical_point()) == Some(*c)) {
                    self.pick(rr, platform, c);
                }
                true
            }
            PointerEvent::Cancel(_) if pressing => {
                self.pressing = None;
                true
            }
            PointerEvent::Move(u) if pressing => {
                // a mouse still shows what it is over
                if u.pointer.pointer_type == PointerType::Mouse {
                    rr.handle_pointer_event(e.clone());
                }
                true
            }
            _ => false,
        }
    }

    fn mouse(&mut self, rr: &mut RenderRoot, platform: &mut dyn Platform, mut e: PointerEvent) {
        let mut clicked = None;
        let mut secondary = None;
        match &mut e {
            PointerEvent::Down(b) => {
                b.state.count = self.count(b);
                self.click = Some(Click { pointer: b.pointer.pointer_id, at: b.state.logical_point(), click: primary(b) });
                if b.button == Some(PointerButton::Secondary) {
                    secondary = Some(b.state.logical_point());
                }
            }
            PointerEvent::Up(b) => {
                self.lifted(b);
                let at = b.state.logical_point();
                clicked = self.click.take().filter(|c| c.pointer == b.pointer.pointer_id && c.click).map(|_| at);
            }
            PointerEvent::Move(u) => {
                if let Some(t) = self.last.as_ref().filter(|t| t.pointer == u.pointer.pointer_id && t.up.is_none()) {
                    for s in std::iter::once(&mut u.current).chain(&mut u.coalesced).chain(&mut u.predicted) {
                        s.count = t.count;
                    }
                }
                let slop = self.thresholds.touch_slop;
                if let Some(c) = self.click.as_mut().filter(|c| c.pointer == u.pointer.pointer_id)
                    && (u.current.logical_point() - c.at).hypot() > slop
                {
                    c.click = false;
                }
            }
            PointerEvent::Cancel(p) | PointerEvent::Leave(p) => {
                if self.last.as_ref().is_some_and(|t| t.pointer == p.pointer_id) {
                    self.last = None;
                }
                self.click = None;
            }
            _ => {}
        }
        rr.handle_pointer_event(e);
        if let Some(at) = clicked {
            tapped(rr, platform, at);
        }
        // a secondary click in a field (which put the caret there, or kept the selection under it)
        if let Some(at) = secondary
            && in_focused_field(rr, at)
        {
            self.open(rr, platform, Some(at));
        }
    }

    fn touch(&mut self, rr: &mut RenderRoot, platform: &mut dyn Platform, e: PointerEvent) {
        let id = info(&e).and_then(|p| p.pointer_id);
        // the primary pointer going down starts over: what was followed ended unseen (a cancel
        // masonry made itself, on losing the window's focus)
        if matches!(e, PointerEvent::Down(_)) && e.is_primary_pointer() {
            self.touch = None;
        }
        if self.touch.as_ref().is_some_and(|t| t.pointer() != id) {
            return;
        }
        let slop = self.thresholds.touch_slop;
        match e {
            PointerEvent::Down(mut b) => {
                let caught = self.fling.take().is_some();
                let handle = handle_under(rr, b.state.logical_point(), slop);
                b.state.count = self.count(&b);
                if caught {
                    self.last = None;
                }
                self.seq += 1;
                // on a handle a touch held still is no long press: it drags the handle or taps
                if handle.is_none() {
                    (self.alarm)(self.seq, self.thresholds.long_press);
                }
                hover(rr, &b);
                self.touch = Some(Touch::Held { down: b, seq: self.seq, caught, handle });
            }
            PointerEvent::Move(u) => match self.touch.take() {
                Some(Touch::Held { down, handle: Some((field, end, offset)), .. }) if (u.current.logical_point() - down.state.logical_point()).hypot() > slop => {
                    self.last = None;
                    leave(rr, down.pointer);
                    self.touch = Some(Touch::Handle { pointer: down.pointer, field, end, offset });
                    drag_handle(rr, field, end, u.current.logical_point() + offset);
                }
                Some(Touch::Held { down, seq, caught, handle }) => {
                    let p = u.current.logical_point();
                    let held = u.current.time.saturating_sub(down.state.time);
                    if (p - down.state.logical_point()).hypot() > slop {
                        // a scroll: no press began, nothing stays hovered
                        self.last = None;
                        leave(rr, down.pointer);
                        let start = down.state.logical_point();
                        self.touch = Some(Touch::Scroll { pointer: down.pointer, at: down.state.clone(), last: start, samples: vec![(down.state.time, start)] });
                        self.scroll_to(rr, p, u.current.time);
                    } else {
                        self.touch = Some(Touch::Held { down, seq, caught, handle });
                        if !caught && handle.is_none() && u128::from(held) >= self.thresholds.long_press.as_nanos() {
                            self.long_press(rr, platform, seq);
                            self.touch(rr, platform, PointerEvent::Move(u));
                        }
                    }
                }
                Some(Touch::Long { pointer }) => {
                    self.touch = Some(Touch::Long { pointer });
                    let mut u = u;
                    for s in std::iter::once(&mut u.current).chain(&mut u.coalesced).chain(&mut u.predicted) {
                        s.buttons = secondary_buttons();
                    }
                    rr.handle_pointer_event(PointerEvent::Move(u));
                }
                Some(t @ Touch::Scroll { .. }) => {
                    self.touch = Some(t);
                    self.scroll_to(rr, u.current.logical_point(), u.current.time);
                }
                Some(Touch::Handle { pointer, field, end, offset }) => {
                    self.touch = Some(Touch::Handle { pointer, field, end, offset });
                    drag_handle(rr, field, end, u.current.logical_point() + offset);
                }
                None => {}
            },
            PointerEvent::Up(mut b) => match self.touch.take() {
                Some(Touch::Held { down, caught, .. }) => {
                    if caught {
                        // it only stopped a fling
                    } else if self.last.as_ref().is_some_and(|t| t.fresh) && on_selection(rr, down.state.logical_point()) {
                        // a tap on the selection opens the menu (closes it, if it was open)
                        // and leaves the selection; a tap following taps selects as it counts
                        self.lifted(&mut b);
                        if !self.was_open {
                            self.open(rr, platform, None);
                        }
                    } else {
                        self.lifted(&mut b);
                        b.state.count = down.state.count;
                        let at = b.state.logical_point();
                        rr.handle_pointer_event(PointerEvent::Down(down));
                        rr.handle_pointer_event(PointerEvent::Up(b.clone()));
                        tapped(rr, platform, at);
                    }
                    leave(rr, b.pointer);
                }
                Some(Touch::Long { .. }) => {
                    b.button = Some(PointerButton::Secondary);
                    let pointer = b.pointer;
                    rr.handle_pointer_event(PointerEvent::Up(b));
                    leave(rr, pointer);
                }
                Some(t @ Touch::Scroll { .. }) => {
                    self.touch = Some(t);
                    self.scroll_to(rr, b.state.logical_point(), b.state.time);
                    if let Some(Touch::Scroll { pointer, at, samples, .. }) = self.touch.take() {
                        let v = velocity(&samples, b.state.time);
                        // a fling that would carry less than half a pixel is none
                        if v.hypot() * FLING_TAU >= 0.5 {
                            self.fling = Some(Fling { pointer, at: PointerState { time: b.state.time, ..at }, v });
                        }
                    }
                }
                Some(Touch::Handle { .. }) | None => {}
            },
            PointerEvent::Cancel(p) => {
                match self.touch.take() {
                    Some(Touch::Long { .. }) => {
                        rr.handle_pointer_event(PointerEvent::Cancel(p));
                    }
                    Some(_) => leave(rr, p),
                    None => {}
                }
                self.last = None;
            }
            e => {
                rr.handle_pointer_event(e);
            }
        }
    }

    /// Counts the press `b` among the taps before it (from the last release to this press,
    /// within the slop; 1, 2, 3, then 1 again: caret, word, line) and starts the next tap.
    fn count(&mut self, b: &PointerButtonEvent) -> u8 {
        let at = b.state.logical_point();
        let ns = u128::from(b.state.time);
        let window = self.thresholds.double_tap.as_nanos();
        let (count, fresh) = match &self.last {
            Some(Tap { up: Some(up), at: last, count, .. }) if ns.saturating_sub(u128::from(*up)) <= window && (at - *last).hypot() <= self.thresholds.double_tap_slop => (count % 3 + 1, false),
            _ => (1, true),
        };
        self.last = Some(Tap { pointer: b.pointer.pointer_id, at, up: None, count, fresh });
        count
    }

    /// The release `b` ends the tap held: its count, and the time the next is counted from.
    fn lifted(&mut self, b: &mut PointerButtonEvent) {
        if let Some(t) = self.last.as_mut().filter(|t| t.pointer == b.pointer.pointer_id) {
            t.up = Some(b.state.time);
            b.state.count = t.count;
        }
    }

    /// The scrolling touch is at `p` (logical) at `time`: what is under it moves along.
    fn scroll_to(&mut self, rr: &mut RenderRoot, p: Point, time: u64) {
        let Some(Touch::Scroll { pointer, at, last, samples }) = &mut self.touch else { return };
        let d = p - *last;
        *last = p;
        samples.retain(|(t, _)| time.saturating_sub(*t) <= VELOCITY_WINDOW);
        samples.push((time, p));
        if d != Vec2::ZERO {
            let (pointer, at) = (*pointer, PointerState { time, ..at.clone() });
            scroll(rr, pointer, at, d);
        }
    }

    /// The long-press timer `seq` ran out: a touch still held where it went down is a long press,
    /// delivered as the touch's secondary press.
    pub fn long_press(&mut self, rr: &mut RenderRoot, platform: &mut dyn Platform, seq: u64) {
        let Some(Touch::Held { down, seq: s, caught: false, handle: None }) = &self.touch else { return };
        if *s != seq {
            return;
        }
        let mut d = down.clone();
        d.button = Some(PointerButton::Secondary);
        d.state.buttons = secondary_buttons();
        d.state.time = d.state.time.saturating_add(u64::try_from(self.thresholds.long_press.as_nanos()).unwrap_or(u64::MAX));
        self.last = None;
        self.touch = Some(Touch::Long { pointer: d.pointer });
        let at = d.state.logical_point();
        rr.handle_pointer_event(PointerEvent::Down(d));
        if in_focused_field(rr, at) {
            self.open(rr, platform, None);
        }
    }

    /// A fling is going on: the shell is to call `frame` every animation frame.
    pub fn flinging(&self) -> bool {
        self.fling.is_some()
    }

    /// An animation frame, `interval` ns after the last: a fling moves on and slows; it stops
    /// once what is left of it is under half a pixel, or what it scrolls can go no further.
    pub fn frame(&mut self, rr: &mut RenderRoot, interval: u64) {
        let Some(f) = &mut self.fling else { return };
        if interval == 0 {
            return;
        }
        let dt = interval as f64 / 1e9;
        let decay = (-dt / FLING_TAU).exp();
        // the distance the decaying speed covers over the frame
        let d = f.v * FLING_TAU * (1.0 - decay);
        f.v *= decay;
        f.at.time = f.at.time.saturating_add(interval);
        let (pointer, at, left) = (f.pointer, f.at.clone(), f.v.hypot() * FLING_TAU);
        if scroll(rr, pointer, at, d) == Handled::No || left < 0.5 {
            self.fling = None;
        }
    }

    /// A text field gained or lost focus (the shell saw an input-method session start or end):
    /// with none focused the keyboard is not wanted. Focus moving between fields leaves it as it is.
    pub fn text_focus(&mut self, rr: &RenderRoot, platform: &mut dyn Platform) {
        if focused_field(rr).is_none() {
            platform.keyboard(false);
        }
    }

    /// Focuses the field `id` for the user to type in now: the keyboard is wanted.
    pub fn type_in(&mut self, rr: &mut RenderRoot, platform: &mut dyn Platform, id: WidgetId) {
        if rr.focus_on(Some(id)) && focused_field(rr) == Some(id) {
            platform.keyboard(true);
        }
    }

    /// A text event (a key, an input method's edit, a command, the window's focus), on its way
    /// to `rr`: Escape closes the menu (and goes no further); what changes the selection moves or
    /// closes it.
    pub fn text_event(&mut self, rr: &mut RenderRoot, platform: &mut dyn Platform, e: TextEvent) -> Handled {
        if let TextEvent::Keyboard(k) = &e
            && k.state == KeyState::Down
            && k.key == Key::Named(NamedKey::Escape)
            && self.menu.is_some()
        {
            self.close(rr, platform);
            return Handled::Yes;
        }
        let h = rr.handle_text_event(e);
        self.follow(rr, platform);
        h
    }

    /// The system's Back: it closes the menu, if one is open (true).
    pub fn back(&mut self, rr: &mut RenderRoot, platform: &mut dyn Platform) -> bool {
        let open = self.menu.is_some();
        self.close(rr, platform);
        open
    }

    /// The menu's item `c` was picked (on the platform's menu, or kit's by a screen reader): the
    /// focused field runs it. The menu closes, but after Select all, which leaves a selection to act
    /// on, it follows that.
    pub fn pick(&mut self, rr: &mut RenderRoot, platform: &mut dyn Platform, c: TextCommand) {
        if self.menu.is_none() {
            return;
        }
        if c != TextCommand::SelectAll {
            self.close(rr, platform);
        }
        rr.handle_text_event(TextEvent::Command(c));
        self.follow(rr, platform);
    }

    /// The platform closed its menu by itself.
    pub fn menu_gone(&mut self) {
        if self.menu.as_ref().is_some_and(|m| m.drawn.is_none()) {
            self.menu = None;
        }
    }

    /// Opens the menu for the focused field's selection, beside it or at `pointer`; none when it
    /// would hold nothing.
    fn open(&mut self, rr: &mut RenderRoot, platform: &mut dyn Platform, pointer: Option<Point>) {
        self.close(rr, platform);
        let Some((field, t)) = rr.focused_ime_text() else { return };
        let (revision, selection) = (t.revision(), t.selection());
        let paste = platform.has_clipboard_text();
        let Some(menu) = menu_of(rr, field, pointer, paste) else { return };
        self.menu = Some(Shown { field, revision, selection, pointer, paste, menu, drawn: None });
        self.present(rr, platform);
    }

    /// Shows the menu as it is: the platform's, or kit's drawing.
    fn present(&mut self, rr: &mut RenderRoot, platform: &mut dyn Platform) {
        let Some(m) = self.menu.as_mut() else { return };
        if let Some(id) = m.drawn.take() {
            rr.remove_layer(id);
        }
        if !platform.show_selection_menu(&m.menu) {
            let w = NewWidget::new(Menu::new(&m.menu, self.look.clone()));
            m.drawn = Some(w.id());
            rr.add_layer(w, Point::ORIGIN);
        }
    }

    fn close(&mut self, rr: &mut RenderRoot, platform: &mut dyn Platform) {
        self.pressing = None;
        match self.menu.take().map(|m| m.drawn) {
            Some(Some(id)) => rr.remove_layer(id),
            Some(None) => platform.hide_selection_menu(),
            None => {}
        }
    }

    /// After anything that may change the focused field: the menu closes when the field lost the
    /// focus, its text changed or its selection collapsed; else it moves with the selection.
    pub fn follow(&mut self, rr: &mut RenderRoot, platform: &mut dyn Platform) {
        let Some(m) = &self.menu else { return };
        let now = rr.focused_ime_text().map(|(id, t)| (id, t.revision(), t.selection()));
        let menu = match now {
            Some((id, rev, sel)) if id == m.field && rev == m.revision && (sel == m.selection || sel.0 != sel.1) => menu_of(rr, id, m.pointer, m.paste).map(|menu| (sel, menu)),
            _ => None,
        };
        let Some((sel, menu)) = menu else { return self.close(rr, platform) };
        let Some(m) = self.menu.as_mut() else { return };
        m.selection = sel;
        if menu != m.menu {
            m.menu = menu;
            self.present(rr, platform);
        }
    }
}

/// The menu for `field`'s selection as it is now, at `pointer` or beside the selection, with
/// Paste when `paste`; `None` when it would hold nothing.
fn menu_of(rr: &RenderRoot, field: WidgetId, pointer: Option<Point>, paste: bool) -> Option<SelectionMenu> {
    let w = rr.get_widget(field)?;
    let area = w.downcast::<TextArea<true>>()?.inner().selection_area()?;
    let (_, t) = rr.focused_ime_text()?;
    let (a, f) = t.selection();
    let at = match pointer {
        Some(p) => Place::Pointer(p),
        None => Place::Selection(w.ctx().window_transform().transform_rect_bbox(area)),
    };
    let mut items = Vec::new();
    if a != f {
        items.extend([TextCommand::Cut, TextCommand::Copy]);
    }
    if paste {
        items.push(TextCommand::Paste);
    }
    if a.min(f) > 0 || a.max(f) < t.text().len() {
        items.push(TextCommand::SelectAll);
    }
    (!items.is_empty()).then_some(SelectionMenu { at, items })
}

/// The pointer an event is from.
fn info(e: &PointerEvent) -> Option<&PointerInfo> {
    match e {
        PointerEvent::Down(b) | PointerEvent::Up(b) => Some(&b.pointer),
        PointerEvent::Move(u) => Some(&u.pointer),
        PointerEvent::Cancel(p) | PointerEvent::Enter(p) | PointerEvent::Leave(p) => Some(p),
        PointerEvent::Scroll(s) => Some(&s.pointer),
        PointerEvent::Gesture(g) => Some(&g.pointer),
    }
}

fn primary(b: &PointerButtonEvent) -> bool {
    matches!(b.button, None | Some(PointerButton::Primary))
}

fn secondary_buttons() -> PointerButtons {
    let mut b = PointerButtons::new();
    b.insert(PointerButton::Secondary);
    b
}

/// A touch held at `b`'s point shows what is under it as hovered.
fn hover(rr: &mut RenderRoot, b: &PointerButtonEvent) {
    rr.handle_pointer_event(PointerEvent::Move(PointerUpdate { pointer: b.pointer, current: b.state.clone(), coalesced: Vec::new(), predicted: Vec::new() }));
}

/// The touch is gone from the screen (or scrolls): nothing is hovered.
fn leave(rr: &mut RenderRoot, pointer: PointerInfo) {
    rr.handle_pointer_event(PointerEvent::Leave(pointer));
}

/// Scrolls what is under `at` by `d` (logical px, the way the content moves).
fn scroll(rr: &mut RenderRoot, pointer: PointerInfo, at: PointerState, d: Vec2) -> Handled {
    let s = at.scale_factor;
    let delta = ScrollDelta::PixelDelta(PhysicalPosition::new(d.x * s, d.y * s));
    let h = rr.handle_pointer_event(PointerEvent::Scroll(PointerScrollEvent { pointer, delta, state: at }));
    leave(rr, pointer);
    h
}

/// The speed (logical px/s) over the samples within `VELOCITY_WINDOW` of `now`.
fn velocity(samples: &[(u64, Point)], now: u64) -> Vec2 {
    let recent: Vec<_> = samples.iter().filter(|(t, _)| now.saturating_sub(*t) <= VELOCITY_WINDOW).collect();
    match (recent.first(), recent.last()) {
        (Some((t0, p0)), Some((t1, p1))) if t1 > t0 => (*p1 - *p0) / ((t1 - t0) as f64 / 1e9),
        _ => Vec2::ZERO,
    }
}

/// A tap or click ended at `at`: over the focused text field, the keyboard is wanted.
fn tapped(rr: &RenderRoot, platform: &mut dyn Platform, at: Point) {
    if in_focused_field(rr, at) {
        platform.keyboard(true);
    }
}

/// Whether `at` (window, logical) is over the focused text field.
fn in_focused_field(rr: &RenderRoot, at: Point) -> bool {
    focused_field(rr).is_some_and(|id| rr.get_widget(id).is_some_and(|w| w.ctx().bounding_rect().contains(at)))
}

/// Whether `at` (window, logical) is on the focused field's selection.
fn on_selection(rr: &RenderRoot, at: Point) -> bool {
    let Some(w) = focused_field(rr).and_then(|id| rr.get_widget(id)) else { return false };
    let local = w.ctx().window_transform().inverse() * at;
    w.downcast::<TextArea<true>>().is_some_and(|t| t.inner().selection_boxes().iter().any(|r| r.contains(local)))
}

/// The focused field's selection handle under `at` (window, logical), within `slop` of it.
fn handle_under(rr: &RenderRoot, at: Point, slop: f64) -> Option<(WidgetId, SelectionEnd, Vec2)> {
    let id = focused_field(rr)?;
    let w = rr.get_widget(id)?;
    let local = w.ctx().window_transform().inverse() * at;
    let (end, offset) = w.downcast::<TextArea<true>>()?.inner().handle_at(local, slop)?;
    Some((id, end, offset))
}

/// Moves the `end` of `field`'s selection to the text at `at` (window, logical).
fn drag_handle(rr: &mut RenderRoot, field: WidgetId, end: SelectionEnd, at: Point) {
    let Some(local) = rr.get_widget(field).map(|w| w.ctx().window_transform().inverse() * at) else { return };
    rr.edit_widget(field, |mut w| TextArea::drag_handle(&mut w.downcast::<TextArea<true>>(), end, local));
}

/// The clipboard's text, `None` when it holds none: an empty clipboard pastes nothing.
pub fn clipboard(platform: &mut dyn Platform) -> Option<String> {
    platform.clipboard().filter(|t| !t.is_empty())
}

/// The focused widget asked to paste: the clipboard's text replaces its selection (ending any
/// composition). An empty clipboard leaves the field as it is.
pub fn paste(rr: &mut RenderRoot, platform: &mut dyn Platform) {
    if let Some(text) = clipboard(platform) {
        rr.handle_text_event(TextEvent::ClipboardPaste(text));
    }
}

/// The text field with the focus.
fn focused_field(rr: &RenderRoot) -> Option<WidgetId> {
    rr.focused_ime_text().map(|(id, _)| id)
}
