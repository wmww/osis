// Copyright 2018 the Xilem Authors and the Druid Authors
// SPDX-License-Identifier: Apache-2.0

use std::any::TypeId;
use std::mem::Discriminant;
use std::ops::Range;

use accesskit::{Node, NodeId, Role};
use masonry_core::util::bounding_box_to_rect;
use parley::{Affinity, PlainEditor, Selection};
use parley::editor::{Generation, SplitString};
use tracing::{Span, trace_span};
use vello::Scene;
use vello::kurbo::{Affine, Circle, Point, Rect, Size, Vec2};
use vello::peniko::Fill;

use crate::core::keyboard::{Key, KeyState, NamedKey};
use crate::core::{
    AccessCtx, AccessEvent, BoxConstraints, BrushIndex, ChildrenIds, CursorIcon, EventCtx, Ime,
    ImeText, LayoutCtx, TextCommand, TextEdit, TextInputHints, PaintCtx, PointerButton, PointerButtonEvent, PointerEvent, PointerUpdate,
    PropertiesMut, PropertiesRef, QueryCtx, RegisterCtx, StyleProperty, TextEvent, Update,
    UpdateCtx, Widget, WidgetId, WidgetMut, is_long_press, render_text,
};
use crate::properties::{
    CaretColor, ContentColor, DisabledContentColor, SelectionColor, UnfocusedSelectionColor,
};
use crate::theme::default_text_styles;
use crate::util::debug_panic;
use crate::{TextAlign, theme};

/// `TextArea` implements the core of interactive text.
///
/// It is used to implement [`TextInput`](super::TextInput) and [`Prose`](super::Prose).
/// It is rare that you will use a raw `TextArea` as a widget in your app; most users
/// should prefer one of those wrappers.
///
/// This ensures that the editable and read-only text have the same text selection and
/// copy/paste behaviour.
///
/// The `USER_EDITABLE` const generic parameter determines whether the text area's contents can be
/// edited by the user of the app.
/// This is true for `TextInput` and false for `Prose`.
///
/// This widget emits [`TextAction`] only when `USER_EDITABLE` is true.
///
/// The exact semantics of how much horizontal space this widget takes up has not been determined.
/// In particular, this has consequences when the text alignment is set.
// TODO: RichTextInput 👀
// TODO: Support for links - https://github.com/linebender/xilem/issues/360
pub struct TextArea<const USER_EDITABLE: bool> {
    // TODO: Placeholder text?
    /// The underlying `PlainEditor`, which provides a high-level interface for us to dispatch into.
    editor: PlainEditor<BrushIndex>,
    /// The generation of `editor` which we have rendered.
    ///
    /// TODO: Split into rendered and layout generation. This will make the `edited` mechanism in [`on_text_event`](Widget::on_text_event).
    rendered_generation: Generation,

    /// Whether to wrap words in this area.
    ///
    /// Note that if clipping is desired, that should be added by the parent widget.
    /// Can be set using [`set_word_wrap`](Self::set_word_wrap).
    word_wrap: bool,
    /// The amount of horizontal space available when [layout](Widget::layout) was
    /// last performed.
    ///
    /// If word wrapping is enabled, we use this for line breaking.
    /// We store this to avoid redoing work in layout and to set the
    /// width when `word_wrap` is re-enabled.
    last_available_width: Option<f32>,

    /// Whether to hint whilst drawing the text.
    ///
    /// Should be disabled whilst an animation involving this text is ongoing.
    /// Can be set using [`set_hint`](Self::set_hint).
    // TODO: What classes of animations? I.e does scrolling count?
    hint: bool,

    /// What key combination should trigger a newline insertion.
    /// If this is set to `InsertNewline::OnEnter` then `Enter` will insert a newline and _not_ trigger a [`TextAction::Entered`] event.
    insert_newline: InsertNewline,

    /// Whether to show the cursor, used for the blink animation.
    anim_cursor_visible: bool,

    /// Previous interval (ms), used for the cursor's blink animation.
    anim_prev_interval: u64,

    /// Time elapsed (ms) to calculate the timeout of the cursor's blink animation.
    anim_elapsed: u64,

    /// The composing region an input method is working on, in bytes ([`ImeText::compose`]).
    /// Only input-method edits set it; any other change to the text or selection ends it.
    compose: Option<Range<usize>>,
    /// Bumped on every change to the text ([`ImeText::revision`]).
    revision: u64,
    /// What the text is for ([`ImeText::hints`]); `multiline` follows `insert_newline`.
    hints: TextInputHints,
    /// Selection handles show (a long press selected): the text revision they were shown at. They
    /// go when the text changes, the selection collapses, a primary press lands or focus leaves.
    handles: Option<u64>,
}

/// One end of the selection, as its handle names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectionEnd {
    /// Where the selection started.
    Anchor,
    /// The caret's end.
    Focus,
}

// --- MARK: BUILDERS
impl TextArea<true> {
    /// Create a new `TextArea` which can be edited.
    ///
    /// Useful for creating a styled [`TextInput`](super::TextInput).
    // This is written out fully to appease rust-analyzer; StyleProperty is imported but not recognised.
    /// To change the font size, use `with_style`, setting [`StyleProperty::FontSize`](parley::StyleProperty::FontSize).
    pub fn new_editable(text: &str) -> Self {
        Self::new(text)
    }
}

impl TextArea<false> {
    /// Create a new `TextArea` which cannot be edited by the user.
    ///
    /// Useful for creating a styled [`Prose`](super::Prose).
    // This is written out fully to appease rust-analyzer; StyleProperty is imported but not recognised.
    /// To change the font size, use `with_style`, setting [`StyleProperty::FontSize`](parley::StyleProperty::FontSize).
    pub fn new_immutable(text: &str) -> Self {
        Self::new(text)
    }
}

impl<const EDITABLE: bool> TextArea<EDITABLE> {
    /// Create a new `TextArea` with the given text and default settings.
    ///
    // This is written out fully to appease rust-analyzer; StyleProperty is imported but not recognised.
    /// To change the font size, use `with_style`, setting [`StyleProperty::FontSize`](parley::StyleProperty::FontSize).
    pub fn new(text: &str) -> Self {
        let mut editor = PlainEditor::new(theme::TEXT_SIZE_NORMAL);
        default_text_styles(editor.edit_styles());
        editor.set_text(text);
        Self {
            editor,
            rendered_generation: Generation::default(),
            word_wrap: true,
            last_available_width: None,
            hint: true,
            insert_newline: InsertNewline::default(),
            anim_cursor_visible: true,
            anim_prev_interval: 0,
            anim_elapsed: 0,
            compose: None,
            revision: 0,
            hints: TextInputHints::default(),
            handles: None,
        }
    }

    /// Get the current text of this text area.
    ///
    /// To update the text of an active text area, use [`reset_text`](Self::reset_text).
    ///
    /// The return value is not just `&str` to handle IME preedits.
    pub fn text(&self) -> SplitString<'_> {
        self.editor.text()
    }

    /// Check if this text area holds nothing, including IME preedit content.
    pub fn is_empty(&self) -> bool {
        self.editor.raw_text().is_empty()
    }

    /// Set a style property for the new text area.
    ///
    /// Style properties set by this method include [text size](parley::StyleProperty::FontSize),
    /// [font family](parley::StyleProperty::FontStack), [font weight](parley::StyleProperty::FontWeight),
    /// and [variable font parameters](parley::StyleProperty::FontVariations).
    /// The styles inserted here apply to the entire text; we currently do not
    /// support inline rich text.
    ///
    /// Setting [`StyleProperty::Brush`](parley::StyleProperty::Brush) is not supported.
    /// Use [`ContentColor`] and [`DisabledContentColor`] properties instead.
    /// This is also not additive for [font stacks](parley::StyleProperty::FontStack), and
    /// instead overwrites any previous font stack.
    ///
    /// To set a style property on an active text area, use [`insert_style`](Self::insert_style).
    #[track_caller]
    pub fn with_style(mut self, property: impl Into<StyleProperty>) -> Self {
        self.insert_style_inner(property.into());
        self
    }

    /// Set a style property for the new text area, returning the old value.
    ///
    /// Most users should prefer [`with_style`](Self::with_style) instead.
    pub fn try_with_style(
        mut self,
        property: impl Into<StyleProperty>,
    ) -> (Self, Option<StyleProperty>) {
        let old = self.insert_style_inner(property.into());
        (self, old)
    }

    /// Control [word wrapping](https://en.wikipedia.org/wiki/Line_wrap_and_word_wrap) for the new text area.
    ///
    /// When enabled, the text will be laid out to fit within the available width.
    /// If word wrapping is disabled, the text will likely flow past the available area.
    /// Note that parent widgets will often clip this, so the overflow will not be visible.
    ///
    /// This widget does not currently support scrolling to the cursor,
    /// so it is recommended to leave word wrapping enabled.
    ///
    /// To modify this on an active text area, use [`set_word_wrap`](Self::set_word_wrap).
    pub fn with_word_wrap(mut self, wrap_words: bool) -> Self {
        self.word_wrap = wrap_words;
        self
    }

    /// Set the [text alignment](https://en.wikipedia.org/wiki/Typographic_alignment) of the text.
    ///
    /// Text alignment might have unexpected results when the text area has no horizontal constraints.
    ///
    /// To modify this on an active text area, use [`set_text_alignment`](Self::set_text_alignment).
    // TODO: Document behaviour based on provided minimum constraint?
    pub fn with_text_alignment(mut self, text_alignment: TextAlign) -> Self {
        self.editor.set_alignment(text_alignment);
        self
    }

    /// Set whether [hinting](https://en.wikipedia.org/wiki/Font_hinting) will be used for this text area.
    ///
    /// Hinting is a process where text is drawn "snapped" to pixel boundaries to improve fidelity.
    /// The default is true, i.e. hinting is enabled by default.
    ///
    /// This should be set to false if the text area will be animated at creation.
    /// The kinds of relevant animations include changing variable font parameters,
    /// translating or scaling.
    /// Failing to do so will likely lead to an unpleasant shimmering effect, as different parts of the
    /// text "snap" at different times.
    ///
    /// To modify this on an active text area, use [`set_hint`](Self::set_hint).
    /// You should do so as an animation starts and ends.
    // TODO: Should we tell each widget if smooth scrolling is ongoing so they can disable their hinting?
    // Alternatively, we should automate disabling hinting at the Vello layer when composing.
    pub fn with_hint(mut self, hint: bool) -> Self {
        self.hint = hint;
        self
    }

    /// Tells input methods what the text is for (see [`TextInputHints`]).
    pub fn with_text_input_hints(mut self, hints: TextInputHints) -> Self {
        self.hints = hints;
        self
    }

    /// Configures how this text area handles the user pressing Enter <kbd>↵</kbd>.
    pub fn with_insert_newline(mut self, insert_newline: InsertNewline) -> Self {
        self.insert_newline = insert_newline;
        self
    }

    /// Shared logic between `with_style` and `insert_style`
    #[track_caller]
    fn insert_style_inner(&mut self, property: StyleProperty) -> Option<StyleProperty> {
        if let StyleProperty::Brush(idx @ BrushIndex(1..))
        | StyleProperty::UnderlineBrush(Some(idx @ BrushIndex(1..)))
        | StyleProperty::StrikethroughBrush(Some(idx @ BrushIndex(1..))) = &property
        {
            debug_panic!(
                "Can't set a non-zero brush index ({idx:?}) on a `TextArea`, as it only supports global styling.\n\
                To modify the active brush, use `set_brush` or `with_brush` instead"
            );
            None
        } else {
            self.editor.edit_styles().insert(property)
        }
    }
}

// --- MARK: HELPERS
impl<const EDITABLE: bool> TextArea<EDITABLE> {
    /// Ends any composition, keeping its text: a change made by anything but the input method.
    fn end_compose(&mut self) -> bool {
        self.compose.take().is_some()
    }

    /// Runs an editing command (its shortcut, or `TextEvent::Command`): cut and copy put a
    /// non-empty selection on the clipboard, paste asks the platform (which answers with
    /// `TextEvent::ClipboardPaste`); cut and paste only where the text is editable.
    fn command(&mut self, ctx: &mut EventCtx<'_>, command: TextCommand) {
        let selected = self.editor.selected_text().filter(|t| !t.is_empty()).map(str::to_string);
        let mut edited = false;
        match command {
            TextCommand::Cut if EDITABLE => {
                if let Some(text) = selected {
                    let (fctx, lctx) = ctx.text_contexts();
                    self.editor.driver(fctx, lctx).delete_selection();
                    edited = true;
                    ctx.set_clipboard(text);
                }
            }
            TextCommand::Copy => {
                if let Some(text) = selected {
                    ctx.set_clipboard(text);
                }
            }
            TextCommand::Paste if EDITABLE => ctx.request_paste(),
            TextCommand::SelectAll => {
                let (fctx, lctx) = ctx.text_contexts();
                self.editor.driver(fctx, lctx).select_all();
            }
            TextCommand::Cut | TextCommand::Paste => return,
        }
        ctx.set_handled();
        self.key_edited(ctx, edited);
    }

    /// After a key or command: what changed is shown, and an edit (`edited`) is reported.
    fn key_edited(&mut self, ctx: &mut EventCtx<'_>, edited: bool) {
        let new_generation = self.editor.generation();
        if new_generation != self.rendered_generation {
            self.end_compose();
            if edited {
                self.revision += 1;
                ctx.submit_action::<TextAction>(TextAction::Changed(
                    self.text().into_iter().collect(),
                ));
                ctx.request_layout();
            } else {
                ctx.request_render();
                ctx.set_ime_area(self.ime_area());
            }
            self.rendered_generation = new_generation;
        }
    }

    /// Applies an input method's edit. Returns whether the text changed, or `None` if the edit
    /// does not fit the text (out of bounds or off a char boundary) and was ignored.
    fn apply_edit(
        &mut self,
        fctx: &mut parley::FontContext,
        lctx: &mut parley::LayoutContext<BrushIndex>,
        edit: &TextEdit,
    ) -> Option<bool> {
        let fits = |t: &str, a: usize, b: usize| a <= b && b <= t.len() && t.is_char_boundary(a) && t.is_char_boundary(b);
        let old = self.editor.raw_text();
        if !fits(old, edit.replace.start, edit.replace.end) {
            return None;
        }
        let new_len = old.len() - edit.replace.len() + edit.text.len();
        let in_new = |i: usize| {
            if i < edit.replace.start {
                old.is_char_boundary(i)
            } else if i < edit.replace.start + edit.text.len() {
                edit.text.is_char_boundary(i - edit.replace.start)
            } else {
                i <= new_len && old.is_char_boundary(i - edit.text.len() + edit.replace.len())
            }
        };
        let (a, f) = edit.selection;
        let compose = edit.compose.clone().filter(|c| !c.is_empty());
        if !in_new(a) || !in_new(f) || compose.as_ref().is_some_and(|c| c.start > c.end || !in_new(c.start) || !in_new(c.end)) {
            return None;
        }
        let changed = old[edit.replace.clone()] != *edit.text;
        if changed {
            // on the buffer, not through layout cursors (which snap to grapheme clusters)
            let mut text = String::with_capacity(new_len);
            text.push_str(&old[..edit.replace.start]);
            text.push_str(&edit.text);
            text.push_str(&old[edit.replace.end..]);
            self.editor.set_text(&text);
            self.revision += 1;
        }
        self.editor.driver(fctx, lctx).select_byte_range(a, f);
        self.compose = compose;
        Some(changed)
    }

    /// The composing region's line boxes, for its underline and the IME area.
    fn compose_geometry(&self) -> Vec<Rect> {
        let (Some(c), Some(layout)) = (&self.compose, self.editor.try_layout()) else {
            return Vec::new();
        };
        let sel = Selection::new(
            parley::Cursor::from_byte_index(layout, c.start, Affinity::Downstream),
            parley::Cursor::from_byte_index(layout, c.end, Affinity::Upstream),
        );
        sel.geometry(layout).into_iter().map(|(b, _)| bounding_box_to_rect(b)).collect()
    }

    /// Get the IME area from the editor, accounting for padding.
    ///
    /// This should only be called when the editor layout is available.
    fn ime_area(&self) -> Rect {
        debug_assert!(
            self.editor.try_layout().is_some(),
            "TextArea::ime_area should only be called when the editor layout is available"
        );
        let caret = bounding_box_to_rect(self.editor.ime_cursor_area());
        self.compose_geometry().into_iter().fold(caret, |a, r| a.union(r))
    }
}

// --- MARK: WIDGETMUT
impl<const EDITABLE: bool> TextArea<EDITABLE> {
    /// Set font styling for an active text area.
    ///
    /// Style properties set by this method include [text size](parley::StyleProperty::FontSize),
    /// [font family](parley::StyleProperty::FontStack), [font weight](parley::StyleProperty::FontWeight),
    /// and [variable font parameters](parley::StyleProperty::FontVariations).
    /// The styles inserted here apply to the entire text; we currently do not
    /// support inline rich text.
    ///
    /// Setting [`StyleProperty::Brush`](parley::StyleProperty::Brush) is not supported.
    /// Use [`ContentColor`] and [`DisabledContentColor`] properties instead.
    /// This is also not additive for [font stacks](parley::StyleProperty::FontStack), and
    /// instead overwrites any previous font stack.
    ///
    /// This is the runtime equivalent of [`with_style`](Self::with_style).
    #[track_caller]
    pub fn insert_style(
        this: &mut WidgetMut<'_, Self>,
        property: impl Into<StyleProperty>,
    ) -> Option<StyleProperty> {
        let old = this.widget.insert_style_inner(property.into());

        this.ctx.request_layout();
        old
    }

    /// [Retain](std::vec::Vec::retain) only the styles for which `f` returns true.
    ///
    /// Styles which are removed return to Parley's default values.
    /// In most cases, these are the defaults for this widget.
    ///
    /// Of note, behaviour is unspecified for unsetting the [`FontSize`](parley::StyleProperty::FontSize).
    pub fn retain_styles(this: &mut WidgetMut<'_, Self>, f: impl FnMut(&StyleProperty) -> bool) {
        this.widget.editor.edit_styles().retain(f);

        this.ctx.request_layout();
    }

    /// Remove the style with the discriminant `property`.
    ///
    /// Styles which are removed return to Parley's default values.
    /// In most cases, these are the defaults for this widget.
    ///
    /// To get the discriminant requires constructing a valid `StyleProperty` for the
    /// the desired property and passing it to [`core::mem::discriminant`].
    /// Getting this discriminant is usually possible in a `const` context.
    ///
    /// Of note, behaviour is unspecified for unsetting the [`FontSize`](parley::StyleProperty::FontSize).
    pub fn remove_style(
        this: &mut WidgetMut<'_, Self>,
        property: Discriminant<StyleProperty>,
    ) -> Option<StyleProperty> {
        let old = this.widget.editor.edit_styles().remove(property);

        this.ctx.request_layout();
        old
    }

    /// Set the text displayed in this widget.
    ///
    /// This is likely to be disruptive if the user is focused on this widget,
    /// as it does not retain selections, and may cause undesirable interactions with IME.
    pub fn reset_text(this: &mut WidgetMut<'_, Self>, new_text: &str) {
        this.widget.end_compose();
        this.widget.editor.set_text(new_text);
        this.widget.revision += 1;

        let (fctx, lctx) = this.ctx.text_contexts();
        this.widget.editor.driver(fctx, lctx).move_to_text_end();

        this.ctx.request_layout();
    }

    /// Control [word wrapping](https://en.wikipedia.org/wiki/Line_wrap_and_word_wrap) for the text area.
    ///
    /// When enabled, the text will be laid out to fit within the available width.
    /// If word wrapping is disabled, the text will likely flow past the available area.
    /// Note that parent widgets will often clip this, so the overflow will not be visible.
    ///
    /// This widget does not currently support scrolling to the cursor,
    /// so it is recommended to leave word wrapping enabled.
    ///
    /// The runtime equivalent of [`with_word_wrap`](Self::with_word_wrap).
    pub fn set_word_wrap(this: &mut WidgetMut<'_, Self>, wrap_words: bool) {
        this.widget.word_wrap = wrap_words;
        let width = if wrap_words {
            this.widget.last_available_width
        } else {
            None
        };
        this.widget.editor.set_width(width);
        this.ctx.request_layout();
    }

    /// Set the [text alignment](https://en.wikipedia.org/wiki/Typographic_alignment) of the text.
    ///
    /// Text alignment might have unexpected results when the text area has no horizontal constraints.
    ///
    /// The runtime equivalent of [`with_text_alignment`](Self::with_text_alignment).
    pub fn set_text_alignment(this: &mut WidgetMut<'_, Self>, text_alignment: TextAlign) {
        this.widget.editor.set_alignment(text_alignment);

        this.ctx.request_layout();
    }

    /// Tells input methods what the text is for; the runtime equivalent of
    /// [`with_text_input_hints`](Self::with_text_input_hints). Takes effect when the next input
    /// method session starts.
    pub fn set_text_input_hints(this: &mut WidgetMut<'_, Self>, hints: TextInputHints) {
        this.widget.hints = hints;
    }

    /// Configures how this text area handles the user pressing Enter <kbd>↵</kbd>.
    pub fn set_insert_newline(this: &mut WidgetMut<'_, Self>, insert_newline: InsertNewline) {
        this.widget.insert_newline = insert_newline;
        this.ctx.request_accessibility_update();
    }

    /// Set whether [hinting](https://en.wikipedia.org/wiki/Font_hinting) will be used for this text area.
    ///
    /// The runtime equivalent of [`with_hint`](Self::with_hint).
    /// For full documentation, see that method.
    pub fn set_hint(this: &mut WidgetMut<'_, Self>, hint: bool) {
        this.widget.hint = hint;
        this.ctx.request_paint_only();
    }

    /// The selection as byte indices: its anchor and its focus (the caret).
    pub fn selection_bytes(&self) -> (usize, usize) {
        let s = self.editor.raw_selection();
        (s.anchor().index(), s.focus().index())
    }

    /// Whether the selection handles show.
    pub fn has_handles(&self) -> bool {
        self.handles == Some(self.revision) && !self.editor.raw_selection().is_collapsed()
    }

    /// Each shown handle: which end, the caret's line box at that end, and the handle's circle
    /// (centre, radius) hanging below it (local coordinates).
    fn handle_shapes(&self) -> Vec<(SelectionEnd, Rect, Point, f64)> {
        let (true, Some(layout)) = (self.has_handles(), self.editor.try_layout()) else {
            return Vec::new();
        };
        let s = self.editor.raw_selection();
        [(SelectionEnd::Anchor, s.anchor()), (SelectionEnd::Focus, s.focus())]
            .into_iter()
            .map(|(end, c)| {
                let caret = bounding_box_to_rect(c.geometry(layout, 1.5));
                // the radius from the line: a handle as big as the text it adjusts
                let r = caret.height() * 0.4;
                (end, caret, Point::new(caret.center().x, caret.y1 + r), r)
            })
            .collect()
    }

    /// Each shown handle's centre (local coordinates).
    pub fn handle_centres(&self) -> Vec<(SelectionEnd, Point)> {
        self.handle_shapes().into_iter().map(|(end, _, c, _)| (end, c)).collect()
    }

    /// The handle at `p` (local), within `slop` of its circle (the nearest when both are), and
    /// the offset from `p` to its caret's middle: where a drag from `p` puts that end.
    pub fn handle_at(&self, p: Point, slop: f64) -> Option<(SelectionEnd, Vec2)> {
        self.handle_shapes()
            .into_iter()
            .map(|(end, caret, c, r)| (end, caret.center() - p, (c - p).hypot() - r))
            .filter(|(_, _, d)| *d <= slop)
            .min_by(|a, b| a.2.total_cmp(&b.2))
            .map(|(end, v, _)| (end, v))
    }

    /// The selection's boxes (local coordinates), one per line it covers; none when collapsed.
    pub fn selection_boxes(&self) -> Vec<Rect> {
        self.editor.selection_geometry().into_iter().map(|(b, _)| bounding_box_to_rect(b)).collect()
    }

    /// What the selection covers on screen (local coordinates): its boxes, or the caret when it
    /// is collapsed, and the handles when they show. `None` before the first layout.
    pub fn selection_area(&self) -> Option<Rect> {
        let layout = self.editor.try_layout()?;
        let caret = bounding_box_to_rect(self.editor.raw_selection().focus().geometry(layout, 1.5));
        let text = self.selection_boxes().into_iter().reduce(|a, b| a.union(b)).unwrap_or(caret);
        Some(self.handle_shapes().into_iter().fold(text, |a, (_, _, c, r)| a.union(Rect::from_center_size(c, (2.0 * r, 2.0 * r)))))
    }

    /// Selects the word at `p` (local); on whitespace, the word nearest it (by characters), as a
    /// long press picks a word to act on.
    fn select_word_near(&mut self, fctx: &mut parley::FontContext, lctx: &mut parley::LayoutContext<BrushIndex>, p: Point) {
        self.editor.driver(fctx, lctx).select_word_at_point(p.x as f32, p.y as f32);
        let (a, f) = self.selection_bytes();
        let text = self.editor.raw_text();
        if !text[a.min(f)..a.max(f)].chars().all(char::is_whitespace) {
            return;
        }
        let Some(layout) = self.editor.try_layout() else { return };
        let at = parley::Cursor::from_point(layout, p.x as f32, p.y as f32).index();
        // the last character of a word before `at` and the first after, each with its distance
        let before = text[..at].char_indices().rev().enumerate().find(|(_, (_, c))| !c.is_whitespace()).map(|(n, (i, c))| (n, i + c.len_utf8(), true));
        let after = text[at..].char_indices().enumerate().find(|(_, (_, c))| !c.is_whitespace()).map(|(n, (i, _))| (n, at + i, false));
        let Some((_, edge, ends)) = [before, after].into_iter().flatten().min_by_key(|(n, ..)| *n) else { return };
        let c = parley::Cursor::from_byte_index(layout, edge, Affinity::Downstream);
        let other = if ends { c.previous_logical_word(layout) } else { c.next_logical_word(layout) };
        let (start, end) = if ends { (other.index(), edge) } else { (edge, other.index()) };
        self.editor.driver(fctx, lctx).select_byte_range(start, end);
    }

    /// Moves the `end` of the selection to the text nearest `p` (local), keeping the other. The
    /// selection never collapses: an end dragged onto the other stays where it was.
    pub fn drag_handle(this: &mut WidgetMut<'_, Self>, end: SelectionEnd, p: Point) {
        let Some(layout) = this.widget.editor.try_layout() else { return };
        let at = parley::Cursor::from_point(layout, p.x as f32, p.y as f32).index();
        let (a, f) = this.widget.selection_bytes();
        let (a, f) = match end {
            SelectionEnd::Anchor => (at, f),
            SelectionEnd::Focus => (a, at),
        };
        if a != f && (a, f) != this.widget.selection_bytes() {
            Self::select_byte_range(this, a, f);
        }
    }

    /// Set the selection to the given byte range.
    ///
    /// No-op if either index is not a char boundary.
    pub fn select_byte_range(this: &mut WidgetMut<'_, Self>, start: usize, end: usize) {
        this.widget.end_compose();
        let (fctx, lctx) = this.ctx.text_contexts();
        this.widget
            .editor
            .driver(fctx, lctx)
            .select_byte_range(start, end);
        this.ctx.request_render();
    }

    /// Set the selection to the first instance of the given text.
    ///
    /// This is mostly useful for testing.
    ///
    /// No-op if the text isn't found.
    pub fn select_text(this: &mut WidgetMut<'_, Self>, text: &str) {
        let Some(start) = this.widget.text().to_string().find(text) else {
            return;
        };
        let end = start + text.len();
        Self::select_byte_range(this, start, end);
    }
}

/// Text in a text area has been changed or submitted with enter.
#[derive(PartialEq, Debug)]
// TODO: Should this be two different structs?
pub enum TextAction {
    /// The text has been changed.
    Changed(String),
    /// The text has been submitted with the enter key.
    ///
    /// Whether this action gets emitted depends on the [`InsertNewline`] setting
    /// and with [`InsertNewline::OnShiftEnter`] also on if the shift key is pressed.
    Entered(String),
    // TODO: TextCursor changed, ImeChanged
}

// --- MARK: IMPL WIDGET
impl<const EDITABLE: bool> Widget for TextArea<EDITABLE> {
    type Action = TextAction;

    fn on_anim_frame(
        &mut self,
        ctx: &mut UpdateCtx<'_>,
        _props: &mut PropertiesMut<'_>,
        interval: u64,
    ) {
        /// The time for a complete blink cycle, in milliseconds.
        /// For the first half (i.e. currently 0.5s) the cursor is shown, and for the second half,
        /// it is hidden.
        const CURSOR_BLINK_TIME: u64 = 1000;

        /// The timeout, in milliseconds, after which the cursor will stop blinking (i.e. stay
        /// solid).
        const CURSOR_BLINK_TIMEOUT: u64 = 10_000; // 10 seconds

        // TODO: These should be reading from the system settings, but we currently
        // aren't aware of a robust way to read that cross-platform.

        if ctx.is_window_focused() && ctx.is_focus_target() {
            if self.anim_elapsed < CURSOR_BLINK_TIMEOUT {
                let interval_ms = interval / 1_000_000; // ns to ms
                self.anim_prev_interval += interval_ms;
                self.anim_elapsed += interval_ms;

                if self.anim_prev_interval >= CURSOR_BLINK_TIME {
                    self.anim_prev_interval = self.anim_prev_interval.rem_euclid(CURSOR_BLINK_TIME);
                }

                // TODO: request timer here
                ctx.request_anim_frame();

                // Request paint only if changed.
                if self.anim_prev_interval < CURSOR_BLINK_TIME / 2 && !self.anim_cursor_visible {
                    self.anim_cursor_visible = true;
                    ctx.request_paint_only();
                } else if self.anim_prev_interval >= CURSOR_BLINK_TIME / 2
                    && self.anim_cursor_visible
                {
                    self.anim_cursor_visible = false;
                    ctx.request_paint_only();
                }
            } else if !self.anim_cursor_visible {
                // Request paint only if changed.
                self.anim_cursor_visible = true;
                ctx.request_paint_only();
            }
        }
    }

    fn on_pointer_event(
        &mut self,
        ctx: &mut EventCtx<'_>,
        _props: &mut PropertiesMut<'_>,
        event: &PointerEvent,
    ) {
        match event {
            // a touch's long press: the word under it (or nearest it), with handles to adjust the
            // selection; moving on extends it by words
            PointerEvent::Down(e) if is_long_press(e) => {
                let p = ctx.local_position(e.state.position);
                let (fctx, lctx) = ctx.text_contexts();
                self.select_word_near(fctx, lctx, p);
                self.end_compose();
                self.handles = EDITABLE.then_some(self.revision);
                self.rendered_generation = self.editor.generation();
                ctx.request_render();
                ctx.set_ime_area(self.ime_area());
                ctx.request_focus();
                ctx.capture_pointer();
                ctx.set_handled();
            }
            // a secondary click (for the selection menu): the caret goes there unless it is on
            // the selection, which stays
            PointerEvent::Down(PointerButtonEvent {
                button: Some(PointerButton::Secondary),
                state,
                ..
            }) if EDITABLE => {
                let p = ctx.local_position(state.position);
                if !self.selection_boxes().iter().any(|r| r.contains(p)) {
                    self.handles = None;
                    let (fctx, lctx) = ctx.text_contexts();
                    self.editor.driver(fctx, lctx).move_to_point(p.x as f32, p.y as f32);
                    self.end_compose();
                    self.rendered_generation = self.editor.generation();
                    ctx.request_render();
                    ctx.set_ime_area(self.ime_area());
                }
                ctx.request_focus();
                ctx.set_handled();
            }
            PointerEvent::Down(PointerButtonEvent {
                button: None | Some(PointerButton::Primary),
                state,
                ..
            }) => {
                if self.handles.take().is_some() {
                    ctx.request_render();
                }
                let cursor_pos = ctx.local_position(state.position);
                let (fctx, lctx) = ctx.text_contexts();
                let mut drv = self.editor.driver(fctx, lctx);
                match state.count {
                    2 => drv.select_word_at_point(cursor_pos.x as f32, cursor_pos.y as f32),
                    3 => {
                        drv.select_hard_line_at_point(cursor_pos.x as f32, cursor_pos.y as f32);
                    }
                    _ => {
                        if state.modifiers.shift() {
                            drv.shift_click_extension(cursor_pos.x as f32, cursor_pos.y as f32);
                        } else {
                            drv.move_to_point(cursor_pos.x as f32, cursor_pos.y as f32);
                        }
                    }
                }
                let new_generation = self.editor.generation();
                if new_generation != self.rendered_generation {
                    self.end_compose();
                    ctx.request_render();
                    ctx.set_ime_area(self.ime_area());
                    self.rendered_generation = new_generation;
                }
                ctx.request_focus();
                ctx.capture_pointer();
            }
            PointerEvent::Move(PointerUpdate { current, .. }) => {
                if ctx.is_active() {
                    let cursor_pos = ctx.local_position(current.position);
                    let (fctx, lctx) = ctx.text_contexts();
                    self.editor
                        .driver(fctx, lctx)
                        .extend_selection_to_point(cursor_pos.x as f32, cursor_pos.y as f32);
                    let new_generation = self.editor.generation();
                    if new_generation != self.rendered_generation {
                        self.end_compose();
                        ctx.request_render();
                        ctx.set_ime_area(self.ime_area());
                        self.rendered_generation = new_generation;
                    }
                }
            }
            _ => {}
        }
    }

    fn on_text_event(
        &mut self,
        ctx: &mut EventCtx<'_>,
        _props: &mut PropertiesMut<'_>,
        event: &TextEvent,
    ) {
        // Reset the blink animation.
        self.anim_prev_interval = 0;
        self.anim_elapsed = 0;
        ctx.request_anim_frame();

        match event {
            TextEvent::Keyboard(key_event) => {
                if key_event.state != KeyState::Down {
                    return;
                }
                let (shift, action_mod) = (
                    key_event.modifiers.shift(),
                    if cfg!(target_os = "macos") {
                        key_event.modifiers.meta()
                    } else {
                        key_event.modifiers.ctrl()
                    },
                );
                // the clipboard and select-all shortcuts are the commands (`TextEvent::Command`)
                if let Key::Character(c) = &key_event.key
                    && action_mod
                {
                    let command = match c.to_ascii_lowercase().as_str() {
                        "x" => Some(TextCommand::Cut),
                        "c" => Some(TextCommand::Copy),
                        "v" => Some(TextCommand::Paste),
                        "a" if !shift => Some(TextCommand::SelectAll),
                        _ => None,
                    };
                    if let Some(command) = command {
                        self.command(ctx, command);
                        return;
                    }
                }
                let (fctx, lctx) = ctx.text_contexts();
                // Whether the text was changed.
                let mut edited = false;
                match &key_event.key {
                    Key::Character(a) if action_mod && shift && a.as_str().eq_ignore_ascii_case("a") => {
                        self.editor.driver(fctx, lctx).collapse_selection();
                    }
                    Key::Named(NamedKey::ArrowLeft) => {
                        let mut drv = self.editor.driver(fctx, lctx);
                        if action_mod {
                            if shift {
                                drv.select_word_left();
                            } else {
                                drv.move_word_left();
                            }
                        } else if shift {
                            drv.select_left();
                        } else {
                            drv.move_left();
                        }
                    }
                    Key::Named(NamedKey::ArrowRight) => {
                        let mut drv = self.editor.driver(fctx, lctx);
                        if action_mod {
                            if shift {
                                drv.select_word_right();
                            } else {
                                drv.move_word_right();
                            }
                        } else if shift {
                            drv.select_right();
                        } else {
                            drv.move_right();
                        }
                    }
                    Key::Named(NamedKey::ArrowUp) => {
                        let mut drv = self.editor.driver(fctx, lctx);
                        if shift {
                            drv.select_up();
                        } else {
                            drv.move_up();
                        }
                    }
                    Key::Named(NamedKey::ArrowDown) => {
                        let mut drv = self.editor.driver(fctx, lctx);
                        if shift {
                            drv.select_down();
                        } else {
                            drv.move_down();
                        }
                    }
                    Key::Named(NamedKey::Home) => {
                        let mut drv = self.editor.driver(fctx, lctx);
                        if action_mod {
                            if shift {
                                drv.select_to_text_start();
                            } else {
                                drv.move_to_text_start();
                            }
                        } else if shift {
                            drv.select_to_line_start();
                        } else {
                            drv.move_to_line_start();
                        }
                    }
                    Key::Named(NamedKey::End) => {
                        let mut drv = self.editor.driver(fctx, lctx);
                        if action_mod {
                            if shift {
                                drv.select_to_text_end();
                            } else {
                                drv.move_to_text_end();
                            }
                        } else if shift {
                            drv.select_to_line_end();
                        } else {
                            drv.move_to_line_end();
                        }
                    }
                    Key::Named(NamedKey::Delete) if EDITABLE => {
                        let mut drv = self.editor.driver(fctx, lctx);
                        if action_mod {
                            drv.delete_word();
                        } else {
                            drv.delete();
                        }

                        edited = true;
                    }
                    Key::Named(NamedKey::Backspace) if EDITABLE => {
                        let mut drv = self.editor.driver(fctx, lctx);
                        if action_mod {
                            drv.backdelete_word();
                        } else {
                            drv.backdelete();
                        }

                        edited = true;
                    }
                    Key::Character(sp) if EDITABLE && sp.as_str() == " " => {
                        self.editor
                            .driver(fctx, lctx)
                            .insert_or_replace_selection(" ");
                        edited = true;
                    }
                    Key::Named(NamedKey::Enter) => {
                        let insert_newline = match self.insert_newline {
                            InsertNewline::OnEnter => true,
                            InsertNewline::OnShiftEnter => shift,
                            InsertNewline::Never => false,
                        };
                        if insert_newline {
                            let (fctx, lctx) = ctx.text_contexts();
                            self.editor
                                .driver(fctx, lctx)
                                .insert_or_replace_selection("\n");
                            edited = true;
                        } else {
                            ctx.submit_action::<Self::Action>(TextAction::Entered(
                                self.text().to_string(),
                            ));
                        }
                    }

                    Key::Named(NamedKey::Tab) => {
                        // Intentionally do nothing so that tabbing from a TextInput/Prose works.
                        // Note that this doesn't allow input of the tab character; we need to be more clever here at some point
                        return;
                    }
                    Key::Character(text) if EDITABLE => {
                        self.editor
                            .driver(fctx, lctx)
                            .insert_or_replace_selection(text);
                        edited = true;
                    }
                    _ => {
                        // Do nothing, don't set as handled.
                        return;
                    }
                }
                ctx.set_handled();
                self.key_edited(ctx, edited);
            }

            TextEvent::Command(command) => self.command(ctx, *command),

            TextEvent::WindowFocusChange(_) => {
                // To use a different selection color when unfocused.
                ctx.request_paint_only();
            }

            TextEvent::Ime(e) => {
                ctx.set_handled();
                let mut edited = false;
                let mut changed = false;
                match e {
                    Ime::Disabled => changed = self.end_compose(),
                    Ime::Edit(edit) if EDITABLE => {
                        let (fctx, lctx) = ctx.text_contexts();
                        match self.apply_edit(fctx, lctx, edit) {
                            Some(e) => {
                                edited = e;
                                changed = true;
                            }
                            None => tracing::debug!("ignored an IME edit off the text: {edit:?}"),
                        }
                    }
                    Ime::Edit(_) | Ime::Enabled => {}
                }
                if edited {
                    let text = self.text().into_iter().collect();
                    ctx.submit_action::<Self::Action>(TextAction::Changed(text));
                }
                let new_generation = self.editor.generation();
                if edited || new_generation != self.rendered_generation {
                    ctx.request_layout();
                    self.rendered_generation = new_generation;
                } else if changed {
                    // only the composing region moved: its underline and the IME area
                    ctx.request_render();
                    ctx.set_ime_area(self.ime_area());
                }
            }

            TextEvent::ClipboardPaste(text) => {
                if EDITABLE {
                    let (fctx, lctx) = ctx.text_contexts();
                    self.end_compose();
                    self.editor
                        .driver(fctx, lctx)
                        .insert_or_replace_selection(text);

                    // TODO - Factor out with other branches
                    let new_generation = self.editor.generation();
                    if new_generation != self.rendered_generation {
                        self.revision += 1;
                        ctx.submit_action::<Self::Action>(TextAction::Changed(
                            self.text().into_iter().collect(),
                        ));
                        ctx.request_layout();
                        self.rendered_generation = new_generation;
                    }
                }
            }
        }
    }

    fn accepts_focus(&self) -> bool {
        EDITABLE
    }

    fn accepts_text_input(&self) -> bool {
        EDITABLE
    }

    fn ime_text(&self) -> Option<&dyn ImeText> {
        EDITABLE.then_some(self as &dyn ImeText)
    }

    fn on_access_event(
        &mut self,
        ctx: &mut EventCtx<'_>,
        _props: &mut PropertiesMut<'_>,
        event: &AccessEvent,
    ) {
        if event.action == accesskit::Action::SetTextSelection {
            if let Some(accesskit::ActionData::SetTextSelection(selection)) = &event.data {
                let (fctx, lctx) = ctx.text_contexts();
                self.editor
                    .driver(fctx, lctx)
                    .select_from_accesskit(selection);
                let new_generation = self.editor.generation();
                if new_generation != self.rendered_generation {
                    self.end_compose();
                    ctx.request_render();
                    ctx.set_ime_area(self.ime_area());
                    self.rendered_generation = new_generation;
                }
            }
        }
    }

    fn register_children(&mut self, _ctx: &mut RegisterCtx<'_>) {}

    fn property_changed(&mut self, ctx: &mut UpdateCtx<'_>, property_type: TypeId) {
        CaretColor::prop_changed(ctx, property_type);
        ContentColor::prop_changed(ctx, property_type);
        DisabledContentColor::prop_changed(ctx, property_type);
        SelectionColor::prop_changed(ctx, property_type);
        UnfocusedSelectionColor::prop_changed(ctx, property_type);
    }

    fn update(&mut self, ctx: &mut UpdateCtx<'_>, _props: &mut PropertiesMut<'_>, event: &Update) {
        match event {
            Update::FocusChanged(focused) => {
                if !focused {
                    self.handles = None;
                }
                ctx.request_render();
            }
            Update::DisabledChanged(_) => {
                // We might need to use the disabled brush, and stop displaying the selection.
                ctx.request_render();
            }
            _ => {}
        }
    }

    fn layout(
        &mut self,
        ctx: &mut LayoutCtx<'_>,
        _props: &mut PropertiesMut<'_>,
        bc: &BoxConstraints,
    ) -> Size {
        let available_width = if bc.max().width.is_finite() {
            Some((bc.max().width) as f32)
        } else {
            None
        };
        let max_advance = if self.word_wrap {
            available_width
        } else {
            None
        };
        if self.last_available_width != available_width && self.word_wrap {
            self.editor.set_width(max_advance);
        }
        self.last_available_width = available_width;
        // TODO: Use the minimum width in the bc for alignment

        let new_generation = self.editor.generation();
        if new_generation != self.rendered_generation {
            self.rendered_generation = new_generation;
        }

        if ctx.fonts_changed() {
            // HACK: We force the editor to relayout by pretending to edit the styles.
            // We know that the lifecycle of dirty tracking in Parley's
            // editor will need to change eventually anyway...
            let _ = self.editor.edit_styles();
        }
        let (fctx, lctx) = ctx.text_contexts();
        let layout = self.editor.layout(fctx, lctx);
        let text_width = max_advance.unwrap_or(layout.full_width());
        let text_size = Size::new(text_width.into(), layout.height().into());
        ctx.set_ime_area(self.ime_area());

        let area_size = Size {
            height: text_size.height,
            width: text_size.width,
        };
        bc.constrain(area_size)
    }

    fn paint(&mut self, ctx: &mut PaintCtx<'_>, props: &PropertiesRef<'_>, scene: &mut Scene) {
        let layout = if let Some(layout) = self.editor.try_layout() {
            layout
        } else {
            debug_panic!("Widget `layout` should have happened before paint");
            let (fctx, lctx) = ctx.text_contexts();
            // The `layout` method takes `&mut self`, so we get borrow-checker errors if we return it from this block.
            self.editor.refresh_layout(fctx, lctx);
            self.editor.try_layout().unwrap()
        };
        if ctx.is_focus_target() {
            let caret_color = props.get::<CaretColor>().color;
            let selection_color = if ctx.is_window_focused() {
                props.get::<SelectionColor>().color
            } else {
                props.get::<UnfocusedSelectionColor>().0.color
            };
            for (rect, _) in self.editor.selection_geometry().iter() {
                scene.fill(
                    Fill::NonZero,
                    Affine::IDENTITY,
                    selection_color,
                    None,
                    &bounding_box_to_rect(*rect),
                );
            }
            if let Some(cursor) = self.editor.cursor_geometry(1.5)
                && self.anim_cursor_visible
                && ctx.is_window_focused()
            {
                scene.fill(
                    Fill::NonZero,
                    Affine::IDENTITY,
                    caret_color,
                    None,
                    &bounding_box_to_rect(cursor),
                );
            };
            // the selection handles, in the caret's colour: a stem down each end and a disc below
            let handle = caret_color;
            for (_, caret, c, r) in self.handle_shapes() {
                let stem = Rect::new(caret.x0, caret.y0, caret.x1, c.y);
                scene.fill(Fill::NonZero, Affine::IDENTITY, handle, None, &stem);
                scene.fill(Fill::NonZero, Affine::IDENTITY, handle, None, &Circle::new(c, r));
            }
        }

        let text_color = if ctx.is_disabled() {
            &props.get::<DisabledContentColor>().0
        } else {
            props.get::<ContentColor>()
        };

        render_text(
            scene,
            Affine::IDENTITY,
            layout,
            &[text_color.color.into()],
            self.hint,
        );
        // the composing text, underlined
        for r in self.compose_geometry() {
            let line = Rect::new(r.x0, r.y1 - 1.5, r.x1, r.y1);
            scene.fill(Fill::NonZero, Affine::IDENTITY, text_color.color, None, &line);
        }
    }

    fn get_cursor(&self, _ctx: &QueryCtx<'_>, _pos: Point) -> CursorIcon {
        CursorIcon::Text
    }

    fn accessibility_role(&self) -> Role {
        if EDITABLE {
            match self.insert_newline {
                InsertNewline::OnShiftEnter | InsertNewline::OnEnter => Role::MultilineTextInput,
                _ => Role::TextInput,
            }
        } else {
            Role::Document
        }
    }

    fn accessibility(
        &mut self,
        ctx: &mut AccessCtx<'_>,
        _props: &PropertiesRef<'_>,
        node: &mut Node,
    ) {
        if !EDITABLE {
            node.set_read_only();
        }
        let updated = self.editor.try_accessibility(
            ctx.tree_update(),
            node,
            || NodeId::from(WidgetId::next()),
            0.,
            0.,
        );

        let Some(()) = updated else {
            // We always perform layout before accessibility, so this panic should be unreachable.
            debug_panic!("Could not generate accessibility nodes for text area");
            return;
        };
    }

    fn children_ids(&self) -> ChildrenIds {
        ChildrenIds::new()
    }

    fn make_trace_span(&self, id: WidgetId) -> Span {
        trace_span!("TextArea", id = id.trace())
    }

    fn get_debug_text(&self) -> Option<String> {
        Some(self.editor.text().chars().take(100).collect())
    }
}

impl<const EDITABLE: bool> ImeText for TextArea<EDITABLE> {
    fn text(&self) -> &str {
        self.editor.raw_text()
    }

    fn selection(&self) -> (usize, usize) {
        self.selection_bytes()
    }

    fn compose(&self) -> Option<Range<usize>> {
        self.compose.clone()
    }

    fn revision(&self) -> u64 {
        self.revision
    }

    fn hints(&self) -> TextInputHints {
        TextInputHints {
            multiline: self.insert_newline == InsertNewline::OnEnter,
            ..self.hints
        }
    }
}

/// When to insert a newline in a text area.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum InsertNewline {
    /// Insert a newline when the user presses Enter.
    ///
    /// Note that if this is enabled, then the text area will never emit a [`TextAction::Entered`] event.
    OnEnter,
    /// Insert a newline when the user presses Shift+Enter.
    OnShiftEnter,
    /// Never insert a newline.
    #[default]
    Never,
}

// TODO: What other tests can we have? Some options:
// - Clicking in the right place changes the selection as expected?
// - Keyboard actions have expected results?

#[cfg(test)]
mod tests {
    use masonry_core::core::NewWidget;
    use masonry_testing::TestHarnessParams;
    use vello::kurbo::Size;

    use super::*;
    use crate::core::{KeyboardEvent, Modifiers, Properties};
    use crate::palette;
    use crate::testing::TestHarness;
    use crate::theme::default_property_set;
    // Tests of alignment happen in Prose.

    #[test]
    fn edit_wordwrap() {
        let base_with_wrapping = {
            let area = NewWidget::new(
                TextArea::new_immutable("String which will wrap").with_word_wrap(true),
            );

            let mut harness =
                TestHarness::create_with_size(default_property_set(), area, Size::new(60.0, 40.0));

            harness.render()
        };

        {
            let area = NewWidget::new(
                TextArea::new_immutable("String which will wrap").with_word_wrap(false),
            );

            let mut harness =
                TestHarness::create_with_size(default_property_set(), area, Size::new(60.0, 40.0));

            let without_wrapping = harness.render();

            // Hack: If we are using `SKIP_RENDER_TESTS`, the output image is a 1x1 white pixel
            // This means that the not equal comparison won't work, so we skip it.
            // We should have a more principled solution here (or even better, get render tests working on windows)
            if !std::env::var("SKIP_RENDER_TESTS").is_ok_and(|it| !it.is_empty()) {
                // We don't use assert_eq because we don't want rich assert
                assert!(
                    base_with_wrapping != without_wrapping,
                    "Word wrapping being disabled should be obvious"
                );
            }

            harness.edit_root_widget(|mut area| {
                TextArea::set_word_wrap(&mut area, true);
            });

            let with_enabled_wrap = harness.render();

            // We don't use assert_eq because we don't want rich assert
            assert!(
                base_with_wrapping == with_enabled_wrap,
                "Updating the word wrap should correctly update"
            );
        };
    }

    #[test]
    fn edit_textarea() {
        let mut test_params = TestHarnessParams::default();
        test_params.window_size = Size::new(200.0, 20.0);

        let base_target = {
            let area = NewWidget::new_with_props(
                TextArea::new_immutable("Test string"),
                Properties::new().with(ContentColor::new(palette::css::AZURE)),
            );

            let mut harness = TestHarness::create_with(default_property_set(), area, test_params);

            harness.render()
        };

        {
            let area = NewWidget::new_with_props(
                TextArea::new_immutable("Different string"),
                Properties::new().with(ContentColor::new(palette::css::AZURE)),
            );

            let mut harness = TestHarness::create_with(default_property_set(), area, test_params);

            harness.edit_root_widget(|mut area| {
                TextArea::reset_text(&mut area, "Test string");
            });

            let with_updated_text = harness.render();

            // We don't use assert_eq because we don't want rich assert
            assert!(
                base_target == with_updated_text,
                "Updating the text should match with base text"
            );

            harness.edit_root_widget(|mut area| {
                area.insert_prop(ContentColor::new(palette::css::BROWN));
            });

            let with_updated_brush = harness.render();

            // Hack: If we are using `SKIP_RENDER_TESTS`, the output image is a 1x1 white pixel
            // This means that the not equal comparison won't work, so we skip it.
            if !std::env::var("SKIP_RENDER_TESTS").is_ok_and(|it| !it.is_empty()) {
                // We don't use assert_eq because we don't want rich assert
                assert!(
                    base_target != with_updated_brush,
                    "Updating the brush should have a visible change"
                );
            }
        };
    }

    #[test]
    fn insert_newline_behavior() {
        #[derive(Debug)]
        struct Scenario {
            insert_newline: InsertNewline,
            key: Key,
            modifiers: Modifiers,
            expect_text_entered_event: bool,
        }
        let scenarios = vec![
            Scenario {
                insert_newline: InsertNewline::OnEnter,
                key: Key::Named(NamedKey::Enter),
                modifiers: Modifiers::default(),
                expect_text_entered_event: false,
            },
            Scenario {
                insert_newline: InsertNewline::OnShiftEnter,
                key: Key::Named(NamedKey::Enter),
                modifiers: Modifiers::default(),
                expect_text_entered_event: true,
            },
            Scenario {
                insert_newline: InsertNewline::OnShiftEnter,
                key: Key::Named(NamedKey::Enter),
                modifiers: Modifiers::SHIFT,
                expect_text_entered_event: false,
            },
            Scenario {
                insert_newline: InsertNewline::Never,
                key: Key::Named(NamedKey::Enter),
                modifiers: Modifiers::default(),
                expect_text_entered_event: true,
            },
            Scenario {
                insert_newline: InsertNewline::Never,
                key: Key::Named(NamedKey::Enter),
                modifiers: Modifiers::SHIFT,
                expect_text_entered_event: true,
            },
        ];
        for scenario in scenarios {
            let area = NewWidget::new(
                TextArea::new_editable("hello world").with_insert_newline(scenario.insert_newline),
            );

            let mut harness = TestHarness::create(default_property_set(), area);
            let text_id = harness.root_id();

            harness.focus_on(Some(text_id));
            harness.process_text_event(TextEvent::Keyboard(KeyboardEvent {
                key: scenario.key,
                modifiers: scenario.modifiers,
                ..Default::default()
            }));

            let area = harness.root_widget();
            let text = area.text().to_string();
            let (action, widget_id) = harness.pop_action::<TextAction>().unwrap();
            assert_eq!(widget_id, text_id);

            // Check that only the one action was emitted so we don't miss an error case
            // where Entered _and_ Changed actions are emitted
            assert!(harness.pop_action_erased().is_none());

            if scenario.expect_text_entered_event {
                assert_eq!(action, TextAction::Entered("hello world".to_string()));
                assert_eq!(text, "hello world");
            } else {
                assert_eq!(action, TextAction::Changed("\nhello world".to_string()));
                assert_eq!(text, "\nhello world");
            }
        }
    }
}
