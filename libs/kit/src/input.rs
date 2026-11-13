//! Pointer input in common code (notes/app.md, Platforms and input): every shell's pointer events
//! pass through `Input` on their way to the `RenderRoot`. It recognises gestures from the
//! platform's thresholds (taps counted into double and triple taps; long press and drag versus
//! scroll go here too, a long press woken by a timer through the shell's `Waker`) and decides when
//! the soft keyboard is wanted: focus never shows it by itself; a tap or click on the focused text
//! field does, and so does a field focused for the user to type in now (`type_in`).

use crate::masonry::app::RenderRoot;
use crate::masonry::core::{PointerEvent, PointerId, PointerUpdate, TextEvent, WidgetId};
use crate::masonry::kurbo::Point;
use crate::platform::{Platform, Thresholds};

/// The last tap: its pointer, where it went down (logical), when it went up (ns, `None` while
/// held), how many taps it ends.
struct Tap {
    pointer: Option<PointerId>,
    at: Point,
    up: Option<u64>,
    count: u8,
}

pub struct Input {
    thresholds: Thresholds,
    last: Option<Tap>,
}

impl Input {
    pub fn new(thresholds: Thresholds) -> Input {
        Input { thresholds, last: None }
    }

    /// Delivers `e` to `rr` as part of the gesture it belongs to.
    pub fn pointer(&mut self, rr: &mut RenderRoot, platform: &mut dyn Platform, mut e: PointerEvent) {
        let mut released = None;
        match &mut e {
            PointerEvent::Down(b) => {
                let at = b.state.logical_point();
                let ns = u128::from(b.state.time);
                let window = self.thresholds.double_tap.as_nanos();
                let count = match &self.last {
                    Some(Tap { up: Some(up), at: last, count, .. })
                        if ns.saturating_sub(u128::from(*up)) <= window && (at - *last).hypot() <= self.thresholds.double_tap_slop =>
                    {
                        // a fourth tap starts over: one, two, three (caret, word, line)
                        count % 3 + 1
                    }
                    _ => 1,
                };
                b.state.count = count;
                self.last = Some(Tap { pointer: b.pointer.pointer_id, at, up: None, count });
            }
            PointerEvent::Up(b) => {
                if let Some(t) = self.last.as_mut().filter(|t| t.pointer == b.pointer.pointer_id) {
                    t.up = Some(b.state.time);
                    b.state.count = t.count;
                }
                released = Some(b.state.logical_point());
            }
            PointerEvent::Move(PointerUpdate { pointer, current, coalesced, predicted }) => {
                if let Some(t) = self.last.as_ref().filter(|t| t.pointer == pointer.pointer_id && t.up.is_none()) {
                    for s in std::iter::once(current).chain(coalesced).chain(predicted) {
                        s.count = t.count;
                    }
                }
            }
            PointerEvent::Cancel(p) | PointerEvent::Leave(p) if self.last.as_ref().is_some_and(|t| t.pointer == p.pointer_id) => self.last = None,
            _ => {}
        }
        rr.handle_pointer_event(e);
        if let Some(at) = released
            && focused_field(rr).is_some_and(|id| rr.get_widget(id).is_some_and(|w| w.ctx().bounding_rect().contains(at)))
        {
            platform.keyboard(true);
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
