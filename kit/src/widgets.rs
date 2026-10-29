//! Simple common widgets, as Masonry `NewWidget`s.

use crate::theme::Theme;
use masonry::core::{NewWidget, Properties, Widget};
use masonry::properties::{Background, Padding};
use masonry::widgets::{Button, Label};

/// A list row: a full-width button showing `text`; `selected` tints it.
pub fn row(text: &str, selected: bool, theme: &Theme) -> NewWidget<Button> {
    let props = Properties::new().with(Background::Color(if selected { theme.selected } else { theme.row })).with(Padding::from_vh(6., 10.));
    NewWidget::new_with_props(Button::new(Label::new(text.to_string()).with_auto_id()), props)
}

/// Sets a row's text and selection in place.
pub fn set_row(mut w: masonry::core::WidgetMut<'_, dyn Widget>, text: &str, selected: bool, theme: &Theme) {
    let mut b = w.downcast::<Button>();
    b.insert_prop(Background::Color(if selected { theme.selected } else { theme.row }));
    let mut child = Button::child_mut(&mut b);
    let mut l = child.downcast::<Label>();
    Label::set_text(&mut l, text.to_string());
}
