//! Android's touch and key events as Masonry's (ui-events); kit's `input` counts the taps.

use osis_kit::masonry::core::keyboard::{Key, KeyState, KeyboardEvent, Modifiers, NamedKey};
use osis_kit::masonry::core::pointer::{PointerButton, PointerButtonEvent, PointerButtons, PointerEvent, PointerId, PointerInfo, PointerState, PointerType, PointerUpdate};
use osis_kit::masonry::dpi::PhysicalPosition;
use osis_kit::masonry::ui_events::keyboard::android::{keycode_to_code, keycode_to_location, keycode_to_named_key};

// MotionEvent actions and tool types
const DOWN: i32 = 0;
const UP: i32 = 1;
const MOVE: i32 = 2;
const CANCEL: i32 = 3;
const POINTER_DOWN: i32 = 5;
const POINTER_UP: i32 = 6;
const TOOL_STYLUS: i32 = 2;
const TOOL_MOUSE: i32 = 3;
const TOOL_ERASER: i32 = 4;

/// One MotionEvent, as the view read it.
pub struct Motion<'a> {
    pub action: i32,
    pub index: usize,
    pub ids: &'a [i32],
    pub tools: &'a [i32],
    /// x, y per pointer, physical pixels.
    pub xy: &'a [f32],
    pub pressure: &'a [f32],
    pub meta: i32,
    /// `SystemClock.uptimeMillis` of the event.
    pub time_ms: i64,
}

/// The Masonry events of one MotionEvent.
pub fn pointer_events(m: &Motion<'_>, scale: f64) -> Vec<PointerEvent> {
    let at = |i: usize| -> Option<(PointerInfo, PointerState)> {
        let id = *m.ids.get(i)?;
        let pointer_type = match m.tools.get(i)? {
            &TOOL_STYLUS | &TOOL_ERASER => PointerType::Pen,
            &TOOL_MOUSE => PointerType::Mouse,
            _ => PointerType::Touch,
        };
        let info = PointerInfo { pointer_id: PointerId::new(u64::try_from(id).ok()? + 1), persistent_device_id: None, pointer_type };
        let mut buttons = PointerButtons::new();
        buttons.insert(PointerButton::Primary);
        let state = PointerState {
            time: u64::try_from(m.time_ms).unwrap_or(0).saturating_mul(1_000_000),
            position: PhysicalPosition::new(f64::from(*m.xy.get(2 * i)?), f64::from(*m.xy.get(2 * i + 1)?)),
            buttons,
            modifiers: modifiers(m.meta),
            count: 1,
            pressure: *m.pressure.get(i)?,
            scale_factor: scale,
            ..Default::default()
        };
        Some((info, state))
    };
    let button = |pointer, state| PointerButtonEvent { button: Some(PointerButton::Primary), pointer, state };
    match m.action {
        DOWN | POINTER_DOWN => at(m.index).map(|(p, s)| vec![PointerEvent::Down(button(p, s))]),
        UP | POINTER_UP => at(m.index).map(|(p, mut s)| {
            s.buttons = PointerButtons::new();
            s.pressure = 0.0;
            vec![PointerEvent::Up(button(p, s))]
        }),
        MOVE => Some((0..m.ids.len()).filter_map(at).map(|(pointer, current)| PointerEvent::Move(PointerUpdate { pointer, current, coalesced: Vec::new(), predicted: Vec::new() })).collect()),
        CANCEL => Some((0..m.ids.len()).filter_map(at).map(|(p, _)| PointerEvent::Cancel(p)).collect()),
        _ => None,
    }
    .unwrap_or_default()
}

// KeyEvent actions and meta state
const KEY_DOWN: i32 = 0;
const KEY_UP: i32 = 1;
const META_SHIFT_ON: i32 = 0x1;
const META_ALT_ON: i32 = 0x2;
const META_CTRL_ON: i32 = 0x1000;
const META_META_ON: i32 = 0x10000;
const META_CAPS_LOCK_ON: i32 = 0x100000;

fn modifiers(meta: i32) -> Modifiers {
    let mut m = Modifiers::empty();
    for (bit, flag) in [(META_SHIFT_ON, Modifiers::SHIFT), (META_ALT_ON, Modifiers::ALT), (META_CTRL_ON, Modifiers::CONTROL), (META_META_ON, Modifiers::META), (META_CAPS_LOCK_ON, Modifiers::CAPS_LOCK)] {
        if meta & bit != 0 {
            m |= flag;
        }
    }
    m
}

/// A KeyEvent as Masonry's; `unicode` is `getUnicodeChar(metaState)`.
pub fn key_event(action: i32, keycode: i32, unicode: i32, meta: i32, repeat: i32) -> Option<KeyboardEvent> {
    let state = match action {
        KEY_DOWN => KeyState::Down,
        KEY_UP => KeyState::Up,
        _ => return None,
    };
    let named = keycode_to_named_key(keycode);
    let ch = u32::try_from(unicode).ok().and_then(char::from_u32).filter(|c| !c.is_control());
    let key = match (named, ch) {
        // keys that type nothing have a name (Enter, Backspace, arrows); the rest type their character
        (NamedKey::Unidentified, Some(c)) => Key::Character(c.to_string()),
        (NamedKey::Unidentified, None) => return None,
        (n, _) => Key::Named(n),
    };
    Some(KeyboardEvent {
        state,
        key,
        code: keycode_to_code(keycode),
        location: keycode_to_location(keycode),
        modifiers: modifiers(meta),
        repeat: repeat > 0,
        is_composing: false,
    })
}
