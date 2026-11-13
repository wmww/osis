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
//! A touch on the focused field's selection handle drags that handle. While held still a touch
//! shows as a hover; lifted, or once it scrolls, nothing is hovered. A touch that lands on a fling
//! stops it and is nothing else. Other fingers while one is followed are left out.
//!
//! The soft keyboard: focus never shows it by itself; a tap or click (a primary press released
//! within the slop of where it went down) over the focused text field does, and so does a field
//! focused for the user to type in now (`type_in`).

use crate::masonry::app::RenderRoot;
use crate::masonry::core::{Handled, PointerButton, PointerButtonEvent, PointerEvent, PointerId, PointerInfo, PointerScrollEvent, PointerState, PointerType, PointerUpdate, ScrollDelta, TextEvent, WidgetId};
use crate::masonry::core::pointer::PointerButtons;
use crate::masonry::dpi::PhysicalPosition;
use crate::masonry::kurbo::{Point, Vec2};
use crate::masonry::widgets::{SelectionEnd, TextArea};
use crate::platform::{MenuItem, Platform, SelectionMenu, Thresholds};
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
/// while held), how many taps it ends.
struct Tap {
    pointer: Option<PointerId>,
    at: Point,
    up: Option<u64>,
    count: u8,
}

/// The mouse press held: a click unless it moved past the slop or was not the primary button.
struct Click {
    pointer: Option<PointerId>,
    at: Point,
    click: bool,
}

/// The touch followed, by what it is so far.
enum Touch {
    /// Down, nothing delivered but a hover. `caught`: it landed on a fling, so it is no tap.
    Held { down: PointerButtonEvent, seq: u64, caught: bool },
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

pub struct Input {
    thresholds: Thresholds,
    alarm: Alarm,
    last: Option<Tap>,
    click: Option<Click>,
    touch: Option<Touch>,
    fling: Option<Fling>,
    /// The last long-press timer started.
    seq: u64,
    /// The selection menu was asked to show.
    menu: bool,
}

impl Input {
    pub fn new(thresholds: Thresholds, alarm: Alarm) -> Input {
        Input { thresholds, alarm, last: None, click: None, touch: None, fling: None, seq: 0, menu: false }
    }

    /// Delivers `e` to `rr` as part of the gesture it belongs to.
    pub fn pointer(&mut self, rr: &mut RenderRoot, platform: &mut dyn Platform, e: PointerEvent) {
        let touch = info(&e).is_some_and(|p| matches!(p.pointer_type, PointerType::Touch | PointerType::Pen));
        if matches!(e, PointerEvent::Down(_)) && std::mem::take(&mut self.menu) {
            platform.hide_selection_menu();
        }
        if touch {
            self.touch(rr, platform, e);
        } else {
            self.mouse(rr, platform, e);
        }
    }

    fn mouse(&mut self, rr: &mut RenderRoot, platform: &mut dyn Platform, mut e: PointerEvent) {
        let mut clicked = None;
        match &mut e {
            PointerEvent::Down(b) => {
                b.state.count = self.count(b);
                self.click = Some(Click { pointer: b.pointer.pointer_id, at: b.state.logical_point(), click: primary(b) });
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
                let at = b.state.logical_point();
                if let Some((field, end, offset)) = handle_under(rr, at, slop) {
                    self.touch = Some(Touch::Handle { pointer: b.pointer, field, end, offset });
                    return;
                }
                b.state.count = self.count(&b);
                if caught {
                    self.last = None;
                }
                self.seq += 1;
                (self.alarm)(self.seq, self.thresholds.long_press);
                hover(rr, &b);
                self.touch = Some(Touch::Held { down: b, seq: self.seq, caught });
            }
            PointerEvent::Move(u) => match self.touch.take() {
                Some(Touch::Held { down, seq, caught }) => {
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
                        self.touch = Some(Touch::Held { down, seq, caught });
                        if !caught && u128::from(held) >= self.thresholds.long_press.as_nanos() {
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
                    if !caught {
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
        let count = match &self.last {
            Some(Tap { up: Some(up), at: last, count, .. }) if ns.saturating_sub(u128::from(*up)) <= window && (at - *last).hypot() <= self.thresholds.double_tap_slop => count % 3 + 1,
            _ => 1,
        };
        self.last = Some(Tap { pointer: b.pointer.pointer_id, at, up: None, count });
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
        let Some(Touch::Held { down, seq: s, caught: false }) = &self.touch else { return };
        if *s != seq {
            return;
        }
        let mut d = down.clone();
        d.button = Some(PointerButton::Secondary);
        d.state.buttons = secondary_buttons();
        d.state.time = d.state.time.saturating_add(u64::try_from(self.thresholds.long_press.as_nanos()).unwrap_or(u64::MAX));
        self.last = None;
        self.touch = Some(Touch::Long { pointer: d.pointer });
        rr.handle_pointer_event(PointerEvent::Down(d));
        self.selection_menu(rr, platform);
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

    /// The selection menu, after a long press left a selection in the focused field. Step 3 of
    /// issues/platform-input.md builds the rest: kit's own menu where the platform has none (both
    /// shells answer false), a tap on the selection opening it, a secondary click.
    fn selection_menu(&mut self, rr: &RenderRoot, platform: &mut dyn Platform) {
        let Some((id, t)) = rr.focused_ime_text() else { return };
        let (a, f) = t.selection();
        if a == f {
            return;
        }
        let all = a.min(f) == 0 && a.max(f) == t.text().len();
        let at = rr.get_widget(id).map(|w| w.ctx().bounding_rect()).unwrap_or_default();
        let mut items = vec![MenuItem::Cut, MenuItem::Copy];
        if clipboard(platform).is_some() {
            items.push(MenuItem::Paste);
        }
        if !all {
            items.push(MenuItem::SelectAll);
        }
        platform.show_selection_menu(&SelectionMenu { at, items });
        self.menu = true;
    }
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

/// Whether `e` is a touch's long press (`Input` delivers it as the touch's secondary press).
pub fn is_long_press(e: &PointerButtonEvent) -> bool {
    e.button == Some(PointerButton::Secondary) && e.pointer.pointer_type != PointerType::Mouse
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
    if focused_field(rr).is_some_and(|id| rr.get_widget(id).is_some_and(|w| w.ctx().bounding_rect().contains(at))) {
        platform.keyboard(true);
    }
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
