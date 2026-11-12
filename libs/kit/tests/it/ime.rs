//! Input methods on a real text area (a headless `RenderRoot`): Android's `InputConnection`
//! operations do what `BaseInputConnection` does, never split a character, keep a composition
//! only while the input method alone changes the text, and `ime::Sync` restarts a keyboard
//! exactly when the text changed under it.
use osis_kit::ime::{Seen, Sync, Tell, android, byte_of_utf16, utf16_of_byte};
use osis_kit::masonry::app::{RenderRoot, RenderRootOptions, RenderRootSignal, WindowSizePolicy};
use osis_kit::masonry::core::keyboard::{Key, NamedKey};
use osis_kit::masonry::core::{Ime, ImeText, NewWidget, TextEdit, TextEvent, WidgetId, WidgetTag};
use osis_kit::masonry::dpi::PhysicalSize;
use osis_kit::masonry::widgets::{TextAction, TextArea};
use std::sync::mpsc::{Receiver, channel};

const AREA: WidgetTag<TextArea<true>> = WidgetTag::new("area");

struct Field {
    root: RenderRoot,
    signals: Receiver<RenderRootSignal>,
}

impl Field {
    fn new(text: &str) -> Field {
        let (tx, signals) = channel();
        // a bundled font: no system fonts in tests
        let font = osis_kit::masonry::core::StyleProperty::FontStack(osis_kit::masonry::parley::FontStack::Source("Inter".into()));
        let area = NewWidget::new_with_tag(TextArea::new_editable(text).with_style(font), AREA);
        let opts = RenderRootOptions {
            default_properties: std::sync::Arc::new(osis_kit::masonry::theme::default_property_set()),
            use_system_fonts: false,
            size_policy: WindowSizePolicy::User,
            size: PhysicalSize::new(400, 200),
            scale_factor: 1.0,
            test_font: None,
        };
        let mut root = RenderRoot::new(area.erased(), move |s| drop(tx.send(s)), opts);
        osis_kit::fonts::register(&mut root);
        let id = root.get_widget_with_tag(AREA).unwrap().id();
        root.focus_on(Some(id));
        let mut f = Field { root, signals };
        f.edit(TextEdit { replace: 0..0, text: String::new(), selection: (text.len(), text.len()), compose: None });
        f
    }

    fn t(&self) -> &dyn ImeText {
        self.root.focused_ime_text().expect("an input method session").1
    }

    fn edit(&mut self, e: TextEdit) {
        self.root.handle_text_event(TextEvent::Ime(Ime::Edit(e)));
    }

    fn edit_opt(&mut self, e: Option<TextEdit>) {
        if let Some(e) = e {
            self.edit(e);
        }
    }

    /// Text, selection, composing region.
    fn state(&self) -> (String, (usize, usize), Option<std::ops::Range<usize>>) {
        let t = self.t();
        (t.text().to_string(), t.selection(), t.compose())
    }

    /// The texts the area reported as changed since the last call.
    fn changed(&mut self) -> Vec<String> {
        self.signals
            .try_iter()
            .filter_map(|s| match s {
                RenderRootSignal::Action(a, _) => a.downcast::<TextAction>().ok().and_then(|a| match *a {
                    TextAction::Changed(t) => Some(t),
                    TextAction::Entered(_) => None,
                }),
                _ => None,
            })
            .collect()
    }

    fn id(&self) -> WidgetId {
        self.root.focused_ime_text().unwrap().0
    }
}

#[test]
fn composing_then_committing_a_word() {
    let mut f = Field::new("");
    let e = android::replace_text(f.t(), "hel", 1, true);
    f.edit(e);
    assert_eq!(f.state(), ("hel".into(), (3, 3), Some(0..3)));
    let e = android::replace_text(f.t(), "hello", 1, true);
    f.edit(e);
    assert_eq!(f.state(), ("hello".into(), (5, 5), Some(0..5)));
    // the composing text is the field's text: the app hears it
    assert_eq!(f.changed(), vec!["hel".to_string(), "hello".to_string()]);
    let e = android::replace_text(f.t(), "hello ", 1, false);
    f.edit(e);
    assert_eq!(f.state(), ("hello ".into(), (6, 6), None));
}

#[test]
fn autocorrect_marks_a_word_and_replaces_it() {
    let mut f = Field::new("teh cat");
    let e = android::set_selection(f.t(), 4, 4);
    f.edit_opt(e);
    // Gboard: mark "teh", commit the correction, put the caret back after the space
    let e = android::set_composing_region(f.t(), 0, 3);
    f.edit(e);
    assert_eq!(f.state(), ("teh cat".into(), (4, 4), Some(0..3)));
    let e = android::replace_text(f.t(), "the", 1, false);
    f.edit(e);
    assert_eq!(f.state(), ("the cat".into(), (3, 3), None));
    let e = android::set_selection(f.t(), 4, 4);
    f.edit_opt(e);
    assert_eq!(f.state().1, (4, 4));
}

#[test]
fn new_cursor_position_counts_from_the_text_ends() {
    for (pos, caret) in [(1, 5), (0, 2), (-1, 1), (-9, 0), (2, 6), (99, 7)] {
        let mut f = Field::new("abcd");
        let e = android::set_selection(f.t(), 2, 2);
        f.edit_opt(e);
        let e = android::replace_text(f.t(), "XYZ", pos, false);
        f.edit(e);
        assert_eq!(f.state(), ("abXYZcd".into(), (caret, caret), None), "newCursorPosition {pos}");
    }
}

#[test]
fn deleting_never_splits_a_character() {
    // 😀 is two UTF-16 units and four bytes
    let mut f = Field::new("a😀b");
    let e = android::set_selection(f.t(), 3, 3);
    f.edit_opt(e);
    assert_eq!(f.state().1, (5, 5));
    let e = android::delete_surrounding(f.t(), 1, 0, false);
    f.edit_opt(e);
    assert_eq!(f.state(), ("ab".into(), (1, 1), None));
    let mut f = Field::new("a😀b");
    let e = android::set_selection(f.t(), 1, 1);
    f.edit_opt(e);
    let e = android::delete_surrounding(f.t(), 0, 1, false);
    f.edit_opt(e);
    assert_eq!(f.state(), ("ab".into(), (1, 1), None));
    // in code points: one is the whole emoji
    let mut f = Field::new("😀😀");
    let e = android::delete_surrounding(f.t(), 1, 0, true);
    f.edit_opt(e);
    assert_eq!(f.state(), ("😀".into(), (4, 4), None));
    // a caret inside a pair (setSelection to an odd unit) lands before it
    let mut f = Field::new("😀");
    let e = android::set_selection(f.t(), 1, 1);
    f.edit_opt(e);
    assert_eq!(f.state().1, (0, 0));
}

#[test]
fn deleting_skips_the_composing_text() {
    let mut f = Field::new("one two");
    let e = android::set_composing_region(f.t(), 4, 7);
    f.edit(e);
    let e = android::delete_surrounding(f.t(), 1, 0, false);
    f.edit_opt(e);
    assert_eq!(f.state(), ("onetwo".into(), (6, 6), Some(3..6)));
}

#[test]
fn out_of_range_selection_is_ignored() {
    let f = Field::new("abc");
    assert!(android::set_selection(f.t(), 0, 4).is_none());
    assert!(android::set_selection(f.t(), -1, 1).is_none());
    assert!(android::set_selection(f.t(), 3, 0).is_some());
}

#[test]
fn utf16_offsets_and_text_around_the_cursor() {
    let mut f = Field::new("é😀中x");
    assert_eq!(android::offsets(f.t()), [5, 5, -1, -1]);
    let e = android::set_composing_region(f.t(), 1, 4);
    f.edit(e);
    assert_eq!(android::offsets(f.t()), [5, 5, 1, 4]);
    assert_eq!(f.state().2, Some(2..9));
    // two units back from "x" is 中 and half of 😀: the half is left out
    let e = android::set_selection(f.t(), 4, 4);
    f.edit_opt(e);
    assert_eq!(android::text_before_cursor(f.t(), 2), "中");
    assert_eq!(android::text_before_cursor(f.t(), 3), "😀中");
    assert_eq!(android::text_after_cursor(f.t(), 9), "x");
    assert_eq!(android::selected_text(f.t()), None);
    let e = android::set_selection(f.t(), 0, 3);
    f.edit_opt(e);
    assert_eq!(android::selected_text(f.t()), Some("é😀"));
    for (s, u, b) in [("é😀中x", 3, 6), ("é😀中x", 2, 2), ("", 4, 0)] {
        assert_eq!(byte_of_utf16(s, u), b, "{s} {u}");
    }
    assert_eq!(utf16_of_byte("é😀中x", 6), 3);
}

#[test]
fn caps_mode_follows_text_utils() {
    use android::{CAP_MODE_SENTENCES as S, CAP_MODE_WORDS as W};
    for (text, req, want) in [
        ("", S | W, S | W),
        ("Hi there. ", S | W, S),
        ("Is it? ", S, S),
        ("e.g. ", S, 0),
        ("Done. (", S, S),
        ("word ", W, W),
        ("word", S | W, 0),
        ("line\n", S, S | W),
    ] {
        let f = Field::new(text);
        assert_eq!(android::caps_mode(f.t(), req), want, "{text:?}");
    }
}

#[test]
fn other_changes_end_a_composition_keeping_its_text() {
    let mut f = Field::new("");
    let e = android::replace_text(f.t(), "wor", 1, true);
    f.edit(e);
    f.root.handle_text_event(TextEvent::key_down(Key::Named(NamedKey::Backspace)));
    assert_eq!(f.state(), ("wo".into(), (2, 2), None));
    let e = android::replace_text(f.t(), "xy", 1, true);
    f.edit(e);
    f.root.handle_text_event(TextEvent::Ime(Ime::Disabled));
    let (text, _, compose) = f.state();
    assert_eq!((text.as_str(), compose), ("woxy", None));
}

#[test]
fn an_edit_off_the_text_is_ignored() {
    let mut f = Field::new("😀");
    f.changed();
    f.edit(TextEdit { replace: 1..2, text: "x".into(), selection: (0, 0), compose: None });
    f.edit(TextEdit { replace: 0..9, text: "x".into(), selection: (0, 0), compose: None });
    f.edit(TextEdit { replace: 0..0, text: String::new(), selection: (2, 2), compose: None });
    assert_eq!(f.state(), ("😀".into(), (4, 4), None));
    assert!(f.changed().is_empty());
}

#[test]
fn sync_restarts_only_on_changes_the_keyboard_did_not_make() {
    let mut f = Field::new("ab");
    let mut sync = Sync::default();
    sync.started(Seen::of(&f.root));
    // the keyboard's own edit: nothing to tell beyond the caret
    let e = android::replace_text(f.t(), "c", 1, false);
    f.edit(e);
    assert_eq!(sync.after_input(Seen::of(&f.root)), Tell::Selection);
    assert_eq!(sync.after_app(Seen::of(&f.root)), Tell::Nothing);
    // the app moving the caret
    let id = f.id();
    f.root.edit_widget(id, |mut w| TextArea::select_byte_range(&mut w.downcast::<TextArea<true>>(), 0, 0));
    assert_eq!(sync.after_app(Seen::of(&f.root)), Tell::Selection);
    // the app replacing the text (a merge, a cleared field)
    f.root.edit_widget(id, |mut w| TextArea::reset_text(&mut w.downcast::<TextArea<true>>(), "new"));
    assert_eq!(sync.after_app(Seen::of(&f.root)), Tell::Restart);
    assert_eq!(sync.after_app(Seen::of(&f.root)), Tell::Nothing);
    // focus leaving the field ends the session
    f.root.focus_on(None);
    assert_eq!(sync.after_app(Seen::of(&f.root)), Tell::Restart);
    assert_eq!(sync.after_app(Seen::of(&f.root)), Tell::Nothing);
}

#[test]
fn an_edit_keeping_the_text_is_no_change() {
    // deleting after the caret at the text's end, while composing: the edit rewrites the
    // composing text with itself
    let mut f = Field::new("ab");
    let e = android::set_composing_region(f.t(), 0, 2);
    f.edit(e);
    f.changed();
    let rev = f.t().revision();
    let e = android::delete_surrounding(f.t(), 0, 1, false);
    f.edit_opt(e);
    assert_eq!(f.state(), ("ab".into(), (2, 2), Some(0..2)));
    assert!(f.changed().is_empty());
    assert_eq!(f.t().revision(), rev);
}

/// A small deterministic generator (no dependency for one test).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn int(&mut self, lo: i32, hi: i32) -> i32 {
        lo + self.below((hi - lo + 1) as usize) as i32
    }
    fn text(&mut self, max: usize) -> String {
        // one to four bytes, one or two UTF-16 units; each its own grapheme, so a caret lands
        // exactly where an edit puts it
        const CHARS: [char; 7] = ['a', 'é', '中', '😀', '🎉', '\n', '𝄞'];
        (0..self.below(max + 1)).map(|_| CHARS[self.below(CHARS.len())]).collect()
    }
}

fn units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// A UTF-16 offset moved back off the middle of a surrogate pair.
fn floor16(s: &[u16], u: usize) -> usize {
    if u > 0 && u < s.len() && (0xDC00..0xE000).contains(&s[u]) { u - 1 } else { u }
}

/// A UTF-16 offset moved forward off the middle of a surrogate pair.
fn ceil16(s: &[u16], u: usize) -> usize {
    if u > 0 && u < s.len() && (0xDC00..0xE000).contains(&s[u]) { u + 1 } else { u }
}

/// Random input-connection calls on texts mixing 1- to 4-byte characters: every edit the
/// connection makes fits the text (none is ignored), and each call does what the InputConnection
/// contract says in UTF-16 units, rounding only to keep a surrogate pair whole.
#[test]
fn connection_calls_follow_the_contract_in_utf16() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..50 {
        let start = rng.text(12);
        let mut f = Field::new(&start);
        for _ in 0..40 {
            let (text, sel, compose) = f.state();
            let u = units(&text);
            let len = u.len() as i32;
            let o = android::offsets(f.t());
            let ordered = (o[0].min(o[1]) as usize, o[0].max(o[1]) as usize);
            let comp16 = (o[2] >= 0).then(|| o[2] as usize..o[3] as usize);
            let op = rng.below(7);
            let e = match op {
                0 => {
                    let t = rng.text(4);
                    let (nc, composing) = (rng.int(-4, 6), rng.below(2) == 0);
                    let e = android::replace_text(f.t(), &t, nc, composing);
                    let r = comp16.clone().unwrap_or(ordered.0..ordered.1);
                    let tl = units(&t).len();
                    let new_len = u.len() - r.len() + tl;
                    let want = if nc > 0 { r.start + tl + nc as usize - 1 } else { r.start.saturating_sub(nc.unsigned_abs() as usize) }.min(new_len);
                    let mut nu = u[..r.start].to_vec();
                    nu.extend(units(&t));
                    nu.extend(&u[r.end..]);
                    let c = floor16(&nu, want) as i32;
                    let wc = if composing && !t.is_empty() { [r.start as i32, (r.start + tl) as i32] } else { [-1, -1] };
                    Some((e, Some([c, c, wc[0], wc[1]]), nu))
                }
                1 => {
                    let (a, b) = (rng.int(-2, len + 2), rng.int(-2, len + 2));
                    let e = android::set_selection(f.t(), a, b);
                    let fits = |i: i32| (0..=len).contains(&i);
                    assert_eq!(e.is_some(), fits(a) && fits(b), "setSelection({a}, {b}) on {text:?}");
                    e.map(|e| (e, Some([floor16(&u, a as usize) as i32, floor16(&u, b as usize) as i32, o[2], o[3]]), u.clone()))
                }
                2 => {
                    let (a, b) = (rng.int(-2, len + 2), rng.int(-2, len + 2));
                    let e = android::set_composing_region(f.t(), a, b);
                    let (a, b) = (a.clamp(0, len) as usize, b.clamp(0, len) as usize);
                    let (a, b) = (a.min(b), a.max(b));
                    // half a pair (0..1 of 😀) is no region
                    let (a, b) = (floor16(&u, a), floor16(&u, b));
                    let wc = if a == b { [-1, -1] } else { [a as i32, b as i32] };
                    Some((e, Some([o[0], o[1], wc[0], wc[1]]), u.clone()))
                }
                3 | 4 => {
                    let (before, after, cp) = (rng.int(-1, 4), rng.int(-1, 4), op == 4);
                    let e = android::delete_surrounding(f.t(), before, after, cp);
                    let keep = match &comp16 {
                        Some(c) => ordered.0.min(c.start)..ordered.1.max(c.end),
                        None => ordered.0..ordered.1,
                    };
                    let (b, a) = (before.max(0) as usize, after.max(0) as usize);
                    let (from, to) = if cp {
                        // whole code points: step back and forward by characters
                        let mut from = keep.start;
                        for _ in 0..b {
                            if from == 0 {
                                break;
                            }
                            from = floor16(&u, from - 1);
                        }
                        let mut to = keep.end;
                        for _ in 0..a {
                            if to == u.len() {
                                break;
                            }
                            to = ceil16(&u, to + 1);
                        }
                        (from, to)
                    } else {
                        (floor16(&u, keep.start.saturating_sub(b)), ceil16(&u, (keep.end + a).min(u.len())))
                    };
                    let mut nu = u[..from].to_vec();
                    nu.extend(&u[keep.clone()]);
                    nu.extend(&u[to..]);
                    let gone = (keep.start - from) as i32;
                    let want = [o[0] - gone, o[1] - gone, if o[2] < 0 { -1 } else { o[2] - gone }, if o[3] < 0 { -1 } else { o[3] - gone }];
                    assert_eq!(e.is_some(), b > 0 || a > 0);
                    e.map(|e| (e, Some(want), nu))
                }
                5 => android::finish_composing(f.t()).map(|e| (e, Some([o[0], o[1], -1, -1]), u.clone())),
                _ => {
                    let n = rng.int(-1, 5);
                    let n16 = n.max(0) as usize;
                    let before = units(android::text_before_cursor(f.t(), n));
                    let after = units(android::text_after_cursor(f.t(), n));
                    let (s, e) = ordered;
                    // n units, else one fewer to keep a pair whole
                    let from = ceil16(&u, s.saturating_sub(n16));
                    assert_eq!(before, u[from..s].to_vec(), "textBefore({n}) of {text:?} at {s}");
                    let to = floor16(&u, (e + n16).min(u.len()));
                    assert_eq!(after, u[e..to.max(e)].to_vec(), "textAfter({n}) of {text:?} at {e}");
                    None
                }
            };
            let Some((e, want, nu)) = e else { continue };
            // the edit fits: applied exactly as sent
            let mut t2 = text.clone();
            t2.replace_range(e.replace.clone(), &e.text);
            let want_state = (t2, e.selection, e.compose.clone().filter(|c| !c.is_empty()));
            f.edit(e);
            assert_eq!(f.state(), want_state, "op {op} on {text:?} sel {sel:?} compose {compose:?}");
            assert_eq!(units(&f.state().0), nu, "op {op} on {text:?}: the text in UTF-16");
            if let Some(w) = want {
                assert_eq!(android::offsets(f.t()), w, "op {op} on {text:?} sel {sel:?} compose {compose:?}");
            }
        }
    }
}
