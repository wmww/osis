//! Theme tokens (notes/app.md Look): one place for the colors and sizes kit widgets and apps
//! use, so an own look later replaces values here rather than call sites. The default is
//! Masonry's stock look plus a selection color.

use masonry::core::DefaultProperties;
use masonry::peniko::Color;

/// The look's tokens.
#[derive(Clone, Debug)]
pub struct Theme {
    /// Window background.
    pub base: Color,
    /// Background of a selected list row.
    pub selected: Color,
    /// Background of an unselected list row.
    pub row: Color,
    /// Space between widgets, logical px.
    pub gap: f64,
    /// Padding inside panels, logical px.
    pub pad: f64,
}

impl Default for Theme {
    fn default() -> Self {
        Theme { base: Color::from_rgb8(2, 6, 23), selected: Color::from_rgb8(37, 99, 235), row: Color::from_rgb8(39, 39, 42), gap: 6.0, pad: 8.0 }
    }
}

impl Theme {
    /// Masonry's default properties for widgets that have no own value.
    pub fn properties(&self) -> DefaultProperties {
        masonry::theme::default_property_set()
    }
}
