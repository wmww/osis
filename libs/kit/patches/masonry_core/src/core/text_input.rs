// Copyright 2026 the osis authors
// SPDX-License-Identifier: Apache-2.0

//! The protocol between an editable text widget and the platform's input methods.
//!
//! One model serves every platform: the focused widget's text is a string with a selection and an
//! optional composing region (the part an input method is still working on, shown underlined).
//! The composing text is part of the text, as on Android, macOS and Windows; an input method that
//! drops it (winit's empty preedit) says so with an edit removing it.
//!
//! A platform shell reads the focused widget through [`ImeText`]
//! ([`RenderRoot::focused_ime_text`](crate::app::RenderRoot::focused_ime_text)) and changes it
//! only with [`TextEdit`]s, sent as [`Ime::Edit`](crate::core::Ime::Edit) text events. A shell
//! translates its platform's operations (Android's `InputConnection`, winit's preedit and commit,
//! Wayland's surrounding text) into edits against what it read.

use std::ops::Range;

/// One input-method edit: replace `replace` with `text`, then set the selection and composing
/// region. All offsets are bytes; `replace` is in the text before the edit, `selection` and
/// `compose` in the text after it.
///
/// An edit with an empty `replace` and empty `text` changes only the selection and composing
/// region. A widget ignores an edit whose ranges are out of bounds or not on char boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TextEdit {
    /// The byte range of the current text to replace.
    pub replace: Range<usize>,
    /// The text put in its place.
    pub text: String,
    /// The selection afterwards: anchor and focus (the caret).
    pub selection: (usize, usize),
    /// The composing region afterwards; `None` or an empty range means none.
    pub compose: Option<Range<usize>>,
}

/// An editable text widget as input methods see it.
pub trait ImeText {
    /// The whole text, composing text included.
    fn text(&self) -> &str;
    /// The selection: anchor and focus (the caret), in bytes.
    fn selection(&self) -> (usize, usize);
    /// The composing region, in bytes, if an input method is composing.
    fn compose(&self) -> Option<Range<usize>>;
    /// A number that changes whenever the text changes (not the selection or composing region).
    fn revision(&self) -> u64;
    /// What the text is for, so the platform can pick a fitting keyboard.
    fn hints(&self) -> TextInputHints;
}

/// What a text field is for. Platforms map these to their own (Android's `EditorInfo`, Wayland's
/// content type, iOS's text input traits); a platform without a match uses its default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct TextInputHints {
    /// The kind of text.
    pub purpose: TextPurpose,
    /// What the keyboard's Enter key does in a single-line field.
    pub enter: EnterKey,
    /// Automatic capitalization.
    pub capitalize: Capitalize,
    /// Whether the input method should offer suggestions and corrections.
    pub suggest: bool,
    /// Whether Enter inserts a line break.
    pub multiline: bool,
}

/// The kind of text a field holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TextPurpose {
    /// Prose.
    #[default]
    Text,
    /// A search query.
    Search,
    /// A URL or link.
    Url,
    /// An email address.
    Email,
    /// A number.
    Number,
    /// A phone number.
    Phone,
    /// A person's name.
    Name,
}

/// The label and meaning of a single-line field's Enter key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum EnterKey {
    /// The platform's default.
    #[default]
    Default,
    /// Finish editing.
    Done,
    /// Go to what was typed.
    Go,
    /// Search for what was typed.
    Search,
    /// Send what was typed.
    Send,
    /// Move to the next field.
    Next,
}

/// Automatic capitalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Capitalize {
    /// None.
    None,
    /// The first letter of each word.
    Words,
    /// The first letter of each sentence.
    #[default]
    Sentences,
    /// Every letter.
    All,
}
