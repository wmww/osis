//! What a platform shell supplies (notes/app.md, Platforms and input): only what really differs by
//! platform, through `Platform`, which each shell implements and gives `Ui::start`. Every decision
//! made with it (gestures, when the soft keyboard is wanted, what is cut, copied or pasted, when
//! the selection menu shows, what it holds and where) is common code (`input`, `render`).

use crate::masonry::core::TextCommand;
use crate::masonry::kurbo::{Point, Rect};
use std::time::Duration;

/// The platform under the UI. Called on the UI thread.
pub trait Platform {
    /// The clipboard's text, if any.
    fn clipboard(&mut self) -> Option<String>;
    /// Whether the clipboard holds text to paste, without reading it where reading tells the
    /// user (Android shows a toast for each read).
    fn has_clipboard_text(&mut self) -> bool;
    /// Puts `text` on the clipboard.
    fn set_clipboard(&mut self, text: String);
    /// The soft keyboard is wanted (`true`) or not. A no-op where the platform decides itself.
    fn keyboard(&mut self, wanted: bool);
    /// Shows the platform's own selection menu, or changes the one shown to `menu`: true when it
    /// did, false when there is none (kit draws its own). The shell reports the item picked
    /// (`Ui::menu_pick`) and a menu the platform closed by itself (`Ui::menu_gone`).
    fn show_selection_menu(&mut self, menu: &SelectionMenu) -> bool;
    /// Hides the selection menu `show_selection_menu` showed.
    fn hide_selection_menu(&mut self);
    /// The platform's gesture thresholds.
    fn thresholds(&self) -> Thresholds;
}

/// A selection menu: its items (the focused field's commands) and where it goes.
#[derive(Clone, Debug, PartialEq)]
pub struct SelectionMenu {
    pub at: Place,
    pub items: Vec<TextCommand>,
}

/// Where a selection menu goes (logical pixels in the window).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Place {
    /// Beside the selection (a touch's): what it covers, handles included.
    Selection(Rect),
    /// At the pointer that asked for it (a secondary click), dropping from there.
    Pointer(Point),
}

impl Place {
    /// What the menu must not cover: the selection, or the pointer's point.
    pub fn rect(self) -> Rect {
        match self {
            Place::Selection(r) => r,
            Place::Pointer(p) => Rect::from_points(p, p),
        }
    }
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
