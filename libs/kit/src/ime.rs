//! Input-method protocols over masonry's text input model (`masonry::core::ImeText`: a text with
//! a selection and a composing region, changed only by `TextEdit`s). Platform-free, so each runs
//! and is tested on any host; a platform shell is the thin glue calling these.
//!
//! - [`Sync`]: when to tell an input method about the focused text, and how much (every
//!   platform keeping a copy of the text: Android, Wayland's surrounding text).
//! - [`android`]: Android's `InputConnection`, following `BaseInputConnection`, the framework's
//!   reference that keyboards are written against.

use masonry::app::RenderRoot;
use masonry::core::WidgetId;
use std::ops::Range;

/// The focused text as an input method last saw it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seen {
    pub widget: WidgetId,
    pub revision: u64,
    pub selection: (usize, usize),
    pub compose: Option<Range<usize>>,
}

impl Seen {
    /// The focused text's state, while an input method session is active for it.
    pub fn of(root: &RenderRoot) -> Option<Seen> {
        let (widget, t) = root.focused_ime_text()?;
        Some(Seen { widget, revision: t.revision(), selection: t.selection(), compose: t.compose() })
    }
}

/// What to tell the input method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tell {
    Nothing,
    /// The selection or composing region moved (Android `updateSelection`).
    Selection,
    /// The text changed under it: start over from the text as it is (Android `restartInput`).
    Restart,
}

/// Keeps an input method's picture of the focused text true.
///
/// The rule: an input method knows the text changes it made itself, and the changes from key
/// events it sent or a hardware keyboard typed (both reach the text through the platform's input
/// flow, which input methods follow); it is told every selection and composing change; any other
/// change to the text (another device's typing merged in, the app clearing a field after Send)
/// restarts it.
#[derive(Default)]
pub struct Sync {
    seen: Option<Seen>,
}

impl Sync {
    /// After the platform's own input (an input-method edit or a key event) was handled, before
    /// the app reacted to it.
    pub fn after_input(&mut self, now: Option<Seen>) -> Tell {
        let tell = match (&self.seen, &now) {
            (Some(s), Some(n)) if s.widget == n.widget => {
                if (&s.selection, &s.compose) != (&n.selection, &n.compose) { Tell::Selection } else { Tell::Nothing }
            }
            (None, None) => Tell::Nothing,
            _ => Tell::Restart,
        };
        self.seen = now;
        tell
    }

    /// After anything else ran: the app's reaction to input, a wakeup, a frame.
    pub fn after_app(&mut self, now: Option<Seen>) -> Tell {
        let tell = match (&self.seen, &now) {
            (Some(s), Some(n)) if s.widget == n.widget && s.revision == n.revision => {
                if (&s.selection, &s.compose) != (&n.selection, &n.compose) { Tell::Selection } else { Tell::Nothing }
            }
            (None, None) => Tell::Nothing,
            _ => Tell::Restart,
        };
        self.seen = now;
        tell
    }

    /// A new input method session took the text as it is (Android `onCreateInputConnection`).
    pub fn started(&mut self, now: Option<Seen>) {
        self.seen = now;
    }
}

/// UTF-16 length of a text (Android counts in UTF-16 code units).
pub fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// The byte offset of a UTF-16 offset: clamped to the text, and moved back to the start of a
/// character it falls inside.
pub fn byte_of_utf16(s: &str, u: usize) -> usize {
    let mut n = 0;
    for (b, c) in s.char_indices() {
        let w = c.len_utf16();
        if n + w > u {
            return b;
        }
        n += w;
    }
    s.len()
}

/// The UTF-16 offset of a byte offset (clamped, moved back to a character start).
pub fn utf16_of_byte(s: &str, b: usize) -> usize {
    let mut b = b.min(s.len());
    while !s.is_char_boundary(b) {
        b -= 1;
    }
    utf16_len(&s[..b])
}

/// Android's `InputConnection` over the focused text. Offsets and lengths are UTF-16 code units,
/// as Java counts them; every function reads the text as it is now, so an operation applies
/// to what the user sees even if the keyboard was told about it late.
pub mod android {
    use super::{byte_of_utf16, utf16_len, utf16_of_byte};
    use masonry::core::{Capitalize, EnterKey, ImeText, TextEdit, TextInputHints, TextPurpose};
    use std::ops::Range;

    fn ordered((a, f): (usize, usize)) -> Range<usize> {
        a.min(f)..a.max(f)
    }

    /// The selection, widened to cover the composing region (what `deleteSurroundingText` and the
    /// text around the cursor count from).
    fn around(t: &dyn ImeText) -> Range<usize> {
        let s = ordered(t.selection());
        match t.compose() {
            Some(c) => s.start.min(c.start)..s.end.max(c.end),
            None => s,
        }
    }

    /// Clamps a Java int offset to `0..=len`.
    fn clamp16(i: i32, len: usize) -> usize {
        usize::try_from(i).unwrap_or(0).min(len)
    }

    /// `setComposingText` (`composing`) and `commitText`: replace the composing text, else the
    /// selection, with `text`; the caret goes `new_cursor` from the text's end if positive (1 is
    /// just after it), else `new_cursor` from its start.
    pub fn replace_text(t: &dyn ImeText, text: &str, new_cursor: i32, composing: bool) -> TextEdit {
        let s = t.text();
        let r = t.compose().unwrap_or_else(|| ordered(t.selection()));
        let (start16, end16, text16) = (utf16_of_byte(s, r.start), utf16_of_byte(s, r.end), utf16_len(text));
        let new_len16 = utf16_len(s) - (end16 - start16) + text16;
        let caret16 = if new_cursor > 0 {
            (start16 + text16).saturating_add(new_cursor as usize - 1)
        } else {
            start16.saturating_sub(new_cursor.unsigned_abs() as usize)
        }
        .min(new_len16);
        // the caret's byte in the edited text: before, inside or after the new text
        let caret = if caret16 <= start16 {
            byte_of_utf16(s, caret16)
        } else if caret16 <= start16 + text16 {
            r.start + byte_of_utf16(text, caret16 - start16)
        } else {
            byte_of_utf16(s, caret16 - text16 + (end16 - start16)) - r.len() + text.len()
        };
        let compose = (composing && !text.is_empty()).then(|| r.start..r.start + text.len());
        TextEdit { replace: r, text: text.to_string(), selection: (caret, caret), compose }
    }

    /// `setComposingRegion`: mark existing text as composing (an empty region: none).
    pub fn set_composing_region(t: &dyn ImeText, start: i32, end: i32) -> TextEdit {
        let s = t.text();
        let len = utf16_len(s);
        let (a, b) = (clamp16(start, len), clamp16(end, len));
        let (a, b) = (a.min(b), a.max(b));
        let compose = (a != b).then(|| byte_of_utf16(s, a)..byte_of_utf16(s, b));
        TextEdit { replace: 0..0, text: String::new(), selection: t.selection(), compose }
    }

    /// `finishComposingText`: the composing text stays, unmarked.
    pub fn finish_composing(t: &dyn ImeText) -> Option<TextEdit> {
        t.compose()?;
        Some(TextEdit { replace: 0..0, text: String::new(), selection: t.selection(), compose: None })
    }

    /// `setSelection`: `start` is the anchor, `end` the caret. Out of range does nothing.
    pub fn set_selection(t: &dyn ImeText, start: i32, end: i32) -> Option<TextEdit> {
        let s = t.text();
        let len = utf16_len(s);
        let ok = |i: i32| usize::try_from(i).is_ok_and(|i| i <= len);
        if !ok(start) || !ok(end) {
            return None;
        }
        let sel = (byte_of_utf16(s, start as usize), byte_of_utf16(s, end as usize));
        Some(TextEdit { replace: 0..0, text: String::new(), selection: sel, compose: t.compose() })
    }

    /// `deleteSurroundingText` (UTF-16 units) and `deleteSurroundingTextInCodePoints`
    /// (`code_points`): delete before the selection and composing text, and after them, never
    /// splitting a character.
    pub fn delete_surrounding(t: &dyn ImeText, before: i32, after: i32, code_points: bool) -> Option<TextEdit> {
        let s = t.text();
        let keep = around(t);
        let (before, after) = (usize::try_from(before).unwrap_or(0), usize::try_from(after).unwrap_or(0));
        if before == 0 && after == 0 {
            return None;
        }
        let start = if code_points {
            s[..keep.start].char_indices().rev().take(before).last().map_or(keep.start, |(i, _)| i)
        } else {
            byte_of_utf16(s, utf16_of_byte(s, keep.start).saturating_sub(before))
        };
        let end = if code_points {
            s[keep.end..].char_indices().nth(after).map_or(s.len(), |(i, _)| keep.end + i)
        } else {
            // moved forward to a character end
            let e16 = utf16_of_byte(s, keep.end) + after;
            let b = byte_of_utf16(s, e16);
            if utf16_of_byte(s, b) < e16 { b + s[b..].chars().next().map_or(0, char::len_utf8) } else { b }
        };
        let gone = keep.start - start;
        let shift = |i: usize| i - gone;
        let (a, f) = t.selection();
        Some(TextEdit {
            replace: start..end,
            text: s[keep.clone()].to_string(),
            selection: (shift(a), shift(f)),
            compose: t.compose().map(|c| shift(c.start)..shift(c.end)),
        })
    }

    /// `getTextBeforeCursor`: up to `n` units before the selection (fewer rather than half a
    /// character).
    pub fn text_before_cursor(t: &dyn ImeText, n: i32) -> &str {
        let s = t.text();
        let at = ordered(t.selection()).start;
        let from16 = utf16_of_byte(s, at).saturating_sub(usize::try_from(n).unwrap_or(0));
        let mut from = byte_of_utf16(s, from16);
        if utf16_of_byte(s, from) < from16 {
            from += s[from..].chars().next().map_or(0, char::len_utf8);
        }
        &s[from..at]
    }

    /// `getTextAfterCursor`: up to `n` units after the selection.
    pub fn text_after_cursor(t: &dyn ImeText, n: i32) -> &str {
        let s = t.text();
        let at = ordered(t.selection()).end;
        let to = byte_of_utf16(s, utf16_of_byte(s, at) + usize::try_from(n).unwrap_or(0));
        &s[at..to.max(at)]
    }

    /// `getSelectedText`: `None` when the selection is a caret.
    pub fn selected_text(t: &dyn ImeText) -> Option<&str> {
        let r = ordered(t.selection());
        (!r.is_empty()).then(|| &t.text()[r])
    }

    /// The selection (anchor, caret) and composing region (-1, -1 for none) in UTF-16 units, as
    /// `updateSelection` and `EditorInfo` want them.
    pub fn offsets(t: &dyn ImeText) -> [i32; 4] {
        let s = t.text();
        let u = |b: usize| i32::try_from(utf16_of_byte(s, b)).unwrap_or(i32::MAX);
        let (a, f) = t.selection();
        let (ca, cb) = t.compose().map_or((-1, -1), |c| (u(c.start), u(c.end)));
        [u(a), u(f), ca, cb]
    }

    pub const CAP_MODE_CHARACTERS: i32 = 0x1000;
    pub const CAP_MODE_WORDS: i32 = 0x2000;
    pub const CAP_MODE_SENTENCES: i32 = 0x4000;

    /// `getCursorCapsMode`: which of `req` apply at the cursor (`TextUtils.getCapsMode`).
    pub fn caps_mode(t: &dyn ImeText, req: i32) -> i32 {
        let s = t.text();
        let before = &s[..ordered(t.selection()).start];
        let mut mode = req & CAP_MODE_CHARACTERS;
        if req & (CAP_MODE_WORDS | CAP_MODE_SENTENCES) == 0 {
            return mode;
        }
        let opening = |c: char| matches!(c, '"' | '\'' | '(' | '[' | '{' | '“' | '‘' | '«' | '¿' | '¡' | '「' | '『' | '（' | '【');
        let closing = |c: char| matches!(c, '"' | '\'' | ')' | ']' | '}' | '”' | '’' | '»' | '」' | '』' | '）' | '】');
        // back over opening punctuation, then over spaces. Java's set is ' " and the Ps/Pe classes;
        // this one adds the quotes (Pi/Pf) and ¿ ¡, so "Done.” Next" and "¿Qué" capitalize
        let i = before.trim_end_matches(opening);
        let j = i.trim_end_matches([' ', '\t']);
        if j.is_empty() || j.ends_with('\n') {
            return mode | CAP_MODE_WORDS | CAP_MODE_SENTENCES;
        }
        if req & CAP_MODE_SENTENCES == 0 {
            if i.len() != j.len() {
                mode |= CAP_MODE_WORDS;
            }
            return mode;
        }
        if i.len() == j.len() {
            return mode;
        }
        let j = j.trim_end_matches(closing);
        match j.chars().next_back() {
            Some('?' | '!') => mode | CAP_MODE_SENTENCES,
            Some('.') => {
                // a word holding another period is an abbreviation ("e.g.")
                let word = j[..j.len() - 1].chars().rev().take_while(|c| *c == '.' || c.is_alphabetic());
                if word.clone().any(|c| c == '.') { mode } else { mode | CAP_MODE_SENTENCES }
            }
            _ => mode,
        }
    }

    // EditorInfo constants (android.text.InputType, EditorInfo)
    const CLASS_TEXT: i32 = 0x1;
    const CLASS_NUMBER: i32 = 0x2;
    const CLASS_PHONE: i32 = 0x3;
    const NUMBER_SIGNED_DECIMAL: i32 = 0x1000 | 0x2000;
    const VARIATION_URI: i32 = 0x10;
    const VARIATION_EMAIL: i32 = 0x20;
    const VARIATION_PERSON_NAME: i32 = 0x60;
    const FLAG_CAP_CHARACTERS: i32 = 0x1000;
    const FLAG_CAP_WORDS: i32 = 0x2000;
    const FLAG_CAP_SENTENCES: i32 = 0x4000;
    const FLAG_AUTO_CORRECT: i32 = 0x8000;
    const FLAG_MULTI_LINE: i32 = 0x20000;
    const FLAG_NO_SUGGESTIONS: i32 = 0x80000;
    const ACTION_UNSPECIFIED: i32 = 0;
    const ACTION_GO: i32 = 2;
    const ACTION_SEARCH: i32 = 3;
    const ACTION_SEND: i32 = 4;
    const ACTION_NEXT: i32 = 5;
    const ACTION_DONE: i32 = 6;
    const FLAG_NO_FULLSCREEN: i32 = 0x0200_0000;
    const FLAG_NO_EXTRACT_UI: i32 = 0x1000_0000;
    const FLAG_NO_ENTER_ACTION: i32 = 0x4000_0000;

    /// `EditorInfo.inputType` and `imeOptions` for a field. Keyboards never go fullscreen: the
    /// field itself stays in view.
    pub fn editor_info(h: TextInputHints) -> (i32, i32) {
        let text = |variation: i32| {
            let caps = match h.capitalize {
                Capitalize::None => 0,
                Capitalize::Words => FLAG_CAP_WORDS,
                Capitalize::Sentences => FLAG_CAP_SENTENCES,
                Capitalize::All => FLAG_CAP_CHARACTERS,
            };
            let suggest = if h.suggest { FLAG_AUTO_CORRECT } else { FLAG_NO_SUGGESTIONS };
            CLASS_TEXT | variation | caps | suggest | if h.multiline { FLAG_MULTI_LINE } else { 0 }
        };
        let input_type = match h.purpose {
            TextPurpose::Text | TextPurpose::Search => text(0),
            TextPurpose::Url => text(VARIATION_URI),
            TextPurpose::Email => text(VARIATION_EMAIL),
            TextPurpose::Name => text(VARIATION_PERSON_NAME),
            TextPurpose::Number => CLASS_NUMBER | NUMBER_SIGNED_DECIMAL,
            TextPurpose::Phone => CLASS_PHONE,
        };
        let action = match h.enter {
            EnterKey::Default => ACTION_UNSPECIFIED,
            EnterKey::Done => ACTION_DONE,
            EnterKey::Go => ACTION_GO,
            EnterKey::Search => ACTION_SEARCH,
            EnterKey::Send => ACTION_SEND,
            EnterKey::Next => ACTION_NEXT,
        };
        // Enter in a multiline field is a line break, not an action
        let enter = if h.multiline { FLAG_NO_ENTER_ACTION } else { 0 };
        (input_type, action | enter | FLAG_NO_FULLSCREEN | FLAG_NO_EXTRACT_UI)
    }
}
