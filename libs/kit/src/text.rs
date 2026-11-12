//! Text for kit widgets that lay out their own text (tiles): one parley layout per string, in
//! the look's text font.

use crate::theme::{Font, Look};
use masonry::core::{BrushIndex, StyleProperty};
use masonry::kurbo::{Affine, Point};
use masonry::parley::{FontStack, FontWeight, Layout, LayoutContext, FontContext};
use masonry::peniko::Color;
use masonry::vello::Scene;
use std::borrow::Cow;

/// The CSS-style family list for a theme font (always ending in the platform's UI font).
pub fn family(font: Font) -> &'static str {
    match font {
        Font::System => "system-ui, sans-serif",
        Font::Inter => "Inter, system-ui, sans-serif",
        Font::DmSans => "DM Sans, system-ui, sans-serif",
        Font::Figtree => "Figtree, system-ui, sans-serif",
        Font::Lexend => "Lexend, system-ui, sans-serif",
        Font::Atkinson => "Atkinson Hyperlegible Next, system-ui, sans-serif",
        Font::Nunito => "Nunito, system-ui, sans-serif",
        Font::Literata => "Literata, serif",
        Font::JetBrainsMono => "JetBrains Mono, monospace",
    }
}

/// `font`'s stack, as a style property for Labels and text areas.
pub fn font_stack(font: Font) -> StyleProperty {
    StyleProperty::FontStack(FontStack::Source(Cow::Borrowed(family(font))))
}

/// A one-line (or wrapped at `wrap`) layout of `text` in the look's text font.
pub fn layout(fcx: &mut FontContext, lcx: &mut LayoutContext<BrushIndex>, look: &Look, text: &str, size: f32, weight: f32, wrap: Option<f32>) -> Layout<BrushIndex> {
    let mut b = lcx.ranged_builder(fcx, text, 1.0, true);
    b.push_default(font_stack(look.theme.text_font));
    b.push_default(StyleProperty::FontSize(size));
    b.push_default(StyleProperty::FontWeight(FontWeight::new(weight)));
    let mut l = b.build(text);
    l.break_all_lines(wrap);
    l
}

/// Draws `l` with its top left at `at`.
pub fn draw(scene: &mut Scene, l: &Layout<BrushIndex>, at: Point, color: Color) {
    masonry::core::render_text(scene, Affine::translate(at.to_vec2()), l, &[color.into()], true);
}
