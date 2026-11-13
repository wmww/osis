//! What a platform shell supplies (notes/app.md, Platforms and input): only what really differs by
//! platform, through `Platform`, which each shell implements and gives `Ui::start`. Every decision
//! made with it (gestures, when the soft keyboard is wanted, what is cut, copied or pasted) is
//! common code (`input`, `render`).

use crate::masonry::kurbo::Rect;
use std::time::Duration;

/// The platform under the UI. Called on the UI thread.
pub trait Platform {
    /// The clipboard's text, if any.
    fn clipboard(&mut self) -> Option<String>;
    /// Puts `text` on the clipboard.
    fn set_clipboard(&mut self, text: String);
    /// The soft keyboard is wanted (`true`) or not. A no-op where the platform decides itself.
    fn keyboard(&mut self, wanted: bool);
    /// Shows the platform's own selection menu: true when it did, false when there is none (kit
    /// draws its own). The shell reports the item picked to `Ui`.
    fn show_selection_menu(&mut self, menu: &SelectionMenu) -> bool;
    /// Hides the selection menu `show_selection_menu` showed.
    fn hide_selection_menu(&mut self);
    /// The platform's gesture thresholds.
    fn thresholds(&self) -> Thresholds;
}

/// A selection menu: its items, beside `at` (the selection, logical pixels in the window).
#[derive(Clone, Debug, PartialEq)]
pub struct SelectionMenu {
    pub at: Rect,
    pub items: Vec<MenuItem>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MenuItem {
    Cut,
    Copy,
    Paste,
    SelectAll,
}

/// The platform's gesture thresholds (distances in logical pixels).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Thresholds {
    /// Longest time from a tap's release to the next press for them to count as a double tap.
    pub double_tap: Duration,
    /// Farthest the next press may be from the last for a double tap.
    pub double_tap_slop: f64,
    /// How long a touch held still is a long press.
    pub long_press: Duration,
    /// How far a touch moves before it is a drag rather than a tap or a long press.
    pub touch_slop: f64,
}
