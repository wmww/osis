//! Stock Masonry widgets (labels, text inputs) styled from a look.

use crate::text::font_stack;
use crate::theme::{Accent, Look};
use masonry::core::{NewWidget, Properties, StyleProperty};
use masonry::parley::FontWeight;
use masonry::peniko::Color;
use masonry::properties::{Background, BorderWidth, CaretColor, ContentColor, Padding, PlaceholderColor, SelectionColor, UnfocusedSelectionColor};
use masonry::widgets::{InsertNewline, Label, TextArea, TextInput};

/// What a piece of text is, for its size, weight and colour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Text {
    /// The app name on home and the rail.
    Brand,
    /// A screen's title.
    Title,
    /// A section heading.
    Section,
    /// Running text.
    Body,
    /// Secondary text.
    Muted,
    /// Small secondary text.
    Small,
}

/// Size, weight and colour of a text role.
pub fn role(look: &Look, t: Text) -> (f32, f32, Color) {
    let caps = matches!(look.theme.accent, Accent::Caps | Accent::Slash);
    let (title_base, label_base) = match look.theme.accent {
        Accent::Rule => (300.0, 400.0),
        Accent::Caps | Accent::Slash => (800.0, 700.0),
        _ => (720.0, 650.0),
    };
    match t {
        Text::Brand => (30.0, look.weight(title_base, 300.0, 100.0, 900.0), look.fg),
        Text::Title => (30.0, look.weight(title_base, 300.0, 100.0, 900.0), look.fg),
        Text::Section => (if caps { 12.0 } else { 13.0 }, look.weight(label_base, 200.0, 100.0, 900.0), look.muted),
        Text::Body => (16.0, 400.0, look.fg),
        Text::Muted => (14.0, 400.0, look.muted),
        Text::Small => (12.5, 400.0, look.muted),
    }
}

/// A label in a text role (section labels upper-cased where the accent asks).
pub fn label(look: &Look, text: &str, t: Text) -> NewWidget<Label> {
    let (size, weight, color) = role(look, t);
    let s = if t == Text::Section && matches!(look.theme.accent, Accent::Caps | Accent::Slash | Accent::Plain) { text.to_uppercase() } else { text.to_string() };
    let l = Label::new(s).with_style(StyleProperty::FontSize(size)).with_style(StyleProperty::FontWeight(FontWeight::new(weight))).with_style(font_stack(look));
    NewWidget::new_with_props(l, Properties::new().with(ContentColor::new(color)).with(Padding::all(0.0)))
}

/// A borderless text input in a text role (`multiline`: Enter inserts a newline).
pub fn input(look: &Look, text: &str, placeholder: &str, t: Text, multiline: bool) -> (NewWidget<TextInput>, masonry::core::WidgetId) {
    let (size, weight, color) = role(look, t);
    let mut area = TextArea::new_editable(text).with_style(StyleProperty::FontSize(size)).with_style(StyleProperty::FontWeight(FontWeight::new(weight))).with_style(font_stack(look));
    if multiline {
        area = area.with_insert_newline(InsertNewline::OnEnter).with_style(StyleProperty::LineHeight(masonry::parley::LineHeight::FontSizeRelative(1.55)));
    }
    let props = Properties::new()
        .with(ContentColor::new(color))
        .with(CaretColor { color: look.accent })
        .with(SelectionColor { color: look.selection })
        .with(UnfocusedSelectionColor(SelectionColor { color: crate::theme::fade(look.selection, 0.5) }));
    let area = NewWidget::new_with_props(area, props);
    let id = area.id();
    let input = TextInput::from_text_area(area).with_placeholder(placeholder.to_string());
    let props = Properties::new()
        .with(BorderWidth { width: 0.0 })
        .with(Background::Color(Color::TRANSPARENT))
        .with(Padding::all(0.0))
        .with(PlaceholderColor::new(look.muted));
    (NewWidget::new_with_props(input, props), id)
}
