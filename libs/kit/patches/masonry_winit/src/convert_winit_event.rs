// Copyright 2025 the Xilem Authors
// SPDX-License-Identifier: Apache-2.0

use masonry_core::core::{Ime, ImeText, ResizeDirection, TextEdit};
use winit::event::Ime as WinitIme;
use winit::window::ResizeDirection as WinitResizeDirection;

pub(crate) fn masonry_resize_direction_to_winit(dir: ResizeDirection) -> WinitResizeDirection {
    match dir {
        ResizeDirection::East => WinitResizeDirection::East,
        ResizeDirection::North => WinitResizeDirection::North,
        ResizeDirection::NorthEast => WinitResizeDirection::NorthEast,
        ResizeDirection::NorthWest => WinitResizeDirection::NorthWest,
        ResizeDirection::South => WinitResizeDirection::South,
        ResizeDirection::SouthEast => WinitResizeDirection::SouthEast,
        ResizeDirection::SouthWest => WinitResizeDirection::SouthWest,
        ResizeDirection::West => WinitResizeDirection::West,
    }
}

/// winit's IME events as edits of the focused text (`masonry_core::core::text_input`). winit's
/// preedit is not text yet: an empty preedit, a commit or the end of the session removes it.
pub(crate) fn winit_ime_to_masonry(event: WinitIme, target: Option<&dyn ImeText>) -> Vec<Ime> {
    let edit = |t: &dyn ImeText, text: String, caret: Option<(usize, usize)>, composing: bool| {
        let (a, f) = t.selection();
        let replace = t.compose().unwrap_or(a.min(f)..a.max(f));
        let start = replace.start;
        let end = start + text.len();
        let selection = caret.map_or((end, end), |(c0, c1)| (start + c0, start + c1));
        let compose = (composing && !text.is_empty()).then_some(start..end);
        Ime::Edit(TextEdit { replace, text, selection, compose })
    };
    match (event, target) {
        (WinitIme::Enabled, _) => vec![Ime::Enabled],
        (WinitIme::Preedit(text, caret), Some(t)) if !text.is_empty() || t.compose().is_some() => {
            vec![edit(t, text, caret, true)]
        }
        (WinitIme::Commit(text), Some(t)) => vec![edit(t, text, None, false)],
        (WinitIme::Disabled, Some(t)) if t.compose().is_some() => {
            vec![edit(t, String::new(), None, false), Ime::Disabled]
        }
        (WinitIme::Disabled, _) => vec![Ime::Disabled],
        (WinitIme::Preedit(..) | WinitIme::Commit(_), _) => Vec::new(),
    }
}
