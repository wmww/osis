//! Stock Masonry widgets (labels, text inputs) styled from a look.

use super::Mark;
use crate::text::font_stack;
use crate::theme::{Font, HeadingMark, LabelCase, Look};
use masonry::core::{NewWidget, Properties, StyleProperty, Widget};
use masonry::parley::FontWeight;
use masonry::peniko::Color;
use masonry::properties::{Background, BorderWidth, CaretColor, ContentColor, Padding, PlaceholderColor, SelectionColor, UnfocusedSelectionColor};
use masonry::properties::types::CrossAxisAlignment;
use masonry::core::TextInputHints;
use masonry::widgets::{Flex, InsertNewline, Label, Prose, TextArea, TextInput};

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

/// Size, weight, colour and font of a text role: titles, the brand and section labels are
/// headings, the rest text.
pub fn role(look: &Look, t: Text) -> (f32, f32, Color, Font) {
    let th = &look.theme;
    let heading = |px| (look.heading_px(px), look.heading_weight(), look.heading, th.heading_font);
    let text = |px, c| (look.text_px(px), look.text_weight(), c, th.text_font);
    match t {
        Text::Brand | Text::Title => heading(30.0),
        Text::Section => heading(13.0),
        Text::Body => text(16.0, look.fg),
        Text::Muted => text(14.0, look.muted),
        Text::Small => text(12.5, look.muted),
    }
}

/// The text styles of a role, plus the underline mark on titles.
fn styles(look: &Look, t: Text) -> Vec<StyleProperty> {
    let (size, weight, _, font) = role(look, t);
    let mut v = vec![StyleProperty::FontSize(size), StyleProperty::FontWeight(FontWeight::new(weight)), font_stack(font)];
    if t == Text::Title && look.theme.mark == HeadingMark::Underline {
        // drawn in the text's own colour: a text area paints with one brush
        v.extend([StyleProperty::Underline(true), StyleProperty::UnderlineSize(Some(size * 0.22)), StyleProperty::UnderlineOffset(Some(size * -0.06))]);
    }
    v
}

/// A label in a text role (section labels in the theme's label case).
pub fn label(look: &Look, text: &str, t: Text) -> NewWidget<Label> {
    let (_, _, color, _) = role(look, t);
    let s = match (t, look.theme.label_case) {
        (Text::Section, LabelCase::Upper) => text.to_uppercase(),
        (Text::Section, LabelCase::Lower) => text.to_lowercase(),
        _ => text.to_string(),
    };
    let mut l = Label::new(s);
    for st in styles(look, t) {
        l = l.with_style(st);
    }
    if t == Text::Section && look.theme.label_case == LabelCase::Upper {
        l = l.with_style(StyleProperty::LetterSpacing(role(look, t).0 * 0.08));
    }
    NewWidget::new_with_props(l, Properties::new().with(ContentColor::new(color)).with(Padding::all(0.0)))
}

/// A heading (a section label, a title, the brand) with the theme's mark: a slash or dot before
/// a section label or a title, the dot also after the brand. `lead`: something already stands
/// before it (an icon or avatar), so no mark goes there.
pub fn marked(look: &Look, w: NewWidget<impl Widget + ?Sized>, t: Text, lead: bool) -> NewWidget<dyn Widget> {
    let mark = look.theme.mark;
    let em = f64::from(role(look, t).0);
    let row = Flex::row().cross_axis_alignment(CrossAxisAlignment::Center);
    match (mark, t) {
        (HeadingMark::Slash | HeadingMark::Dot, Text::Section | Text::Title) if !lead => {
            let m = NewWidget::new(Mark::new(look, mark == HeadingMark::Dot, em));
            NewWidget::new(row.with_child(m).with_flex_child(w.erased(), 1.0)).erased()
        }
        (HeadingMark::Dot, Text::Brand) => {
            let m = NewWidget::new(Mark::after(look, em));
            NewWidget::new(row.cross_axis_alignment(CrossAxisAlignment::End).with_child(w.erased()).with_child(m)).erased()
        }
        _ => w.erased(),
    }
}

/// A heading label with its mark.
pub fn heading(look: &Look, text: &str, t: Text) -> NewWidget<dyn Widget> {
    marked(look, label(look, text, t), t, false)
}

/// Read-only text in a text role that can be selected and copied (click, then Ctrl+C), broken at
/// word boundaries. It takes all the width it is offered: not for a non-flex child of a row.
pub fn prose(look: &Look, text: &str, t: Text) -> NewWidget<Prose> {
    let color = role(look, t).2;
    let mut area = TextArea::new_immutable(text);
    for st in styles(look, t) {
        area = area.with_style(st);
    }
    let props = Properties::new()
        .with(ContentColor::new(color))
        .with(SelectionColor { color: look.selection })
        .with(UnfocusedSelectionColor(SelectionColor { color: crate::theme::fade(look.selection, 0.5) }));
    NewWidget::new(Prose::from_text_area(NewWidget::new_with_props(area, props)))
}

/// A borderless text input in a text role (`multiline`: Enter inserts a newline), telling input
/// methods what it is for.
pub fn input(look: &Look, text: &str, placeholder: &str, t: Text, multiline: bool, hints: TextInputHints) -> (NewWidget<TextInput>, masonry::core::WidgetId) {
    let color = role(look, t).2;
    let mut area = TextArea::new_editable(text).with_text_input_hints(hints);
    for st in styles(look, t) {
        area = area.with_style(st);
    }
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
